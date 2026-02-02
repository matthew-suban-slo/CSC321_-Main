import datetime
import multiprocessing as mp
import os
from sys import argv, exit
import time

import bcrypt

# Reuse the parsing + output logic from the sequential script
from task1_f import User, parseShadow, parseWordFile, writeOutPut


def _worker_check_range(worker_idx, user_saltedhash_bytes, word_list, start_idx, end_idx, found_event, result_queue, progress_every=0):
	guesses = 0
	last_report = 0
	for i in range(start_idx, end_idx):
		if found_event.is_set():
			break
		word = word_list[i]
		guesses += 1
		if progress_every > 0 and guesses - last_report >= progress_every:
			last_report = guesses
			# report local progress without spamming
			result_queue.put(("PROGRESS", worker_idx, guesses))
		if bcrypt.checkpw(word, user_saltedhash_bytes):
			if not found_event.is_set():
				found_event.set()
				result_queue.put(("FOUND", word))
			break
	result_queue.put(("GUESSES", worker_idx, guesses))


def crack_user_parallel(user, word_list, processes=None):
	"""
	Parallelize per-user cracking by splitting the dictionary into chunks.
	This matches the assignment hint: parallelize the dictionary, not users.
	"""
	if processes is None:
		processes = max(1, (os.cpu_count() or 1) - 1)
	processes = max(1, int(processes))
	processes = min(processes, len(word_list))

	start_dt = datetime.datetime.now()
	start_ts = time.time()
	found_event = mp.Event()
	result_queue = mp.Queue()
	progress_every = 2000  # each worker reports every N guesses (keep overhead low)

	chunk_size = (len(word_list) + processes - 1) // processes
	procs = []
	user_saltedhash_bytes = user.saltedhash.encode()

	for pidx in range(processes):
		s = pidx * chunk_size
		e = min((pidx + 1) * chunk_size, len(word_list))
		if s >= e:
			break
		p = mp.Process(
			target=_worker_check_range,
			args=(pidx, user_saltedhash_bytes, word_list, s, e, found_event, result_queue, progress_every),
		)
		p.start()
		procs.append(p)

	total_guesses = 0
	found_word = None
	guesses_expected = len(procs)
	last_print = time.time()
	worker_progress = [0] * len(procs)  # live progress per worker (best-effort)
	worker_done = [False] * len(procs)
	while guesses_expected > 0:
		msg = result_queue.get()
		tag = msg[0]
		if tag == "FOUND" and found_word is None:
			found_word = msg[1]
		elif tag == "PROGRESS":
			_, wid, guesses = msg
			# monotonic update
			if 0 <= wid < len(worker_progress) and guesses > worker_progress[wid]:
				worker_progress[wid] = guesses
		elif tag == "GUESSES":
			_, wid, guesses = msg
			if 0 <= wid < len(worker_progress):
				worker_progress[wid] = max(worker_progress[wid], guesses)
				worker_done[wid] = True
			total_guesses += guesses
			guesses_expected -= 1

		# Periodic CLI update
		now = time.time()
		if now - last_print >= 5:
			elapsed = now - start_ts
			live_guesses = sum(worker_progress)
			rate = (live_guesses / elapsed) if elapsed > 0 else 0.0
			status = "FOUND" if found_word is not None else "running"
			print(f"[{user.name}] {status} | guesses so far: {live_guesses} | {rate:.1f} guesses/sec | elapsed {elapsed:.1f}s")
			last_print = now

	for p in procs:
		p.join()

	user.guessCount += total_guesses
	if found_word is not None:
		user.password = found_word
	user.duration = datetime.datetime.now() - start_dt


def main(argv):
	if len(argv) < 3:
		print("[Usage]: python task1_f_parallel.py [SHADOW_FILE] [NLTK_WORD_FILE] [optional_num_processes]")
		return 1

	procs = None
	if len(argv) >= 4:
		try:
			procs = int(argv[3])
		except ValueError:
			procs = None

	shadowFile = open(argv[1], "r", encoding="utf-8", errors="ignore")
	wordFile = open(argv[2], "r", encoding="utf-8", errors="ignore")
	user_list = parseShadow(shadowFile)
	word_list = parseWordFile(wordFile)

	for user in user_list:
		print(f"\nCracking user: {user.name} (workfactor {user.saltedhash[4:6]}) using {procs or (os.cpu_count() or 1) - 1} processes...")
		crack_user_parallel(user, word_list, processes=procs)
		pw = user.password.decode("utf-8", errors="replace") if isinstance(user.password, (bytes, bytearray)) else "<not found>"
		print(f"Done: {user.name} | password: {pw} | guesses: {user.guessCount} | duration: {user.duration}")

	writeOutPut(user_list)
	wordFile.close()
	shadowFile.close()
	return 0


if __name__ == "__main__":
	exit(main(argv))
