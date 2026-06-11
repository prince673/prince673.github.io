---
title: "HackTheBox — Lucky Dice (Misc / Very Easy)"
date: 2026-06-11 12:00:00 +0530
categories: [CTF, HackTheBox]
tags: [misc, sockets, python, scripting, race-condition, input-buffering]
author: Prince_kumar
math: false
mermaid: false
---

> **When a game of chance becomes a lesson in input buffering and socket timing.**  
> This is the walkthrough for Lucky Dice — a "Very Easy" HackTheBox challenge that illustrates how a misplaced time measurement in a Python script allows a client to bypass a strict 0.3-second response timeout.

---

## Challenge Info

| Field        | Value                        |
|--------------|------------------------------|
| Platform     | HackTheBox                   |
| Box Name     | Lucky Dice                   |
| Category     | Misc                         |
| Difficulty   | Very Easy                    |
| Techniques   | Input Buffering Bypass, Regex Parsing, Stable Sorting / Tie-Breaker logic |
| Tools Used   | python3, sockets             |

---

## 🕚 11:00 — Analysis of the Challenge

We are given a Python script `challenge.py` (which runs on the remote server at `154.57.164.70:30100`). The game challenges us to correctly guess the winner of 100 consecutive rounds of a dice game.

Each round:
1. The server rolls multiple dice for several players.
2. It prints each player's scores/dice values.
3. It prompts for the winner.
4. We must submit the correct winner within a strict `0.3` seconds timeout.

### The Vulnerability: Timing the Input Buffer

If we analyze the timeout implementation in the server code, we find a classic logical bug:

```python
start = time.time()
answer = input('> ')
if time.time() - start > timeout:
    print("Mate... your are too slow! ...")
    return False
```

The server calculates the elapsed time **only after** it executes `input()`. 
However, the server transmits all of the players' dice rolls *before* it halts at the `input()` prompt. 

Because TCP is a stream protocol and input is buffered:
1. The client can receive and parse the dice rolls as soon as they are sent.
2. The client computes the correct winner.
3. The client sends the winner to the socket.
4. The answer arrives at the server's OS input buffer *before* the server code even calls `input()`.
5. When the server finally reaches `input('> ')`, the answer is already waiting in the buffer. The `input()` call returns instantly, and the measured time difference (`time.time() - start`) is practically `0` seconds.

This completely neutralizes the `0.3` seconds timeout.

### The Tie-Breaker Rule

A second nuance to watch out for is the tie-breaker:
* When multiple players share the maximum score, the **last player** (in order of appearance) with that score is considered the winner. 
* To ensure our solver behaves identically to the server, we must scan the parsed scores in order and overwrite the winner variable each time a player's score is *greater than or equal* to the current maximum.

---

## 🕦 11:30 — Exploit Implementation

Below is the automated solver script written in Python. It connects to the server, receives the game output, extracts the dice rolls using regular expressions, calculates the winner, and submits the answer instantly.

```python
#!/usr/bin/env python3
import socket
import re

HOST = "154.57.164.70"
PORT = 30100

def solve():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    s.settimeout(10)

    def recv_until_prompt():
        """Receive data until the server sends '> ' (the input prompt)."""
        data = b""
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                if data.endswith(b"> "):
                    break
            except socket.timeout:
                break
        return data.decode("utf-8", errors="replace")

    # --- Answer "Yes" to "Are you ready?" ---
    intro = recv_until_prompt()
    print(intro)
    s.sendall(b"1\n")

    # --- Play 100 rounds ---
    for rnd in range(100):
        output = recv_until_prompt()
        print(output)

        lines = output.split("\n")
        players_ordered = []   # list of (player_number, total_score) in order of appearance

        for line in lines:
            m = re.match(r"Player\s+(\d+):\s+([\d\s]+)", line.strip())
            if m:
                player_num = int(m.group(1))
                dice = list(map(int, m.group(2).strip().split()))
                players_ordered.append((player_num, sum(dice)))

        if not players_ordered:
            print("[!] Could not parse player scores!")
            print(repr(output))
            break

        max_score = max(score for _, score in players_ordered)
        winner = None
        # Scan in order: last player with max_score wins (tie-breaker)
        for player_num, score in players_ordered:
            if score == max_score:
                winner = player_num

        print(f"  --> Round {rnd+1}: Winner = Player {winner} (score={max_score})")
        s.sendall(f"{winner}\n".encode())

    # --- Retrieve the flag ---
    final = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            final += chunk
    except:
        pass
    print("\n=== FLAG ===")
    print(final.decode("utf-8", errors="replace"))
    s.close()

if __name__ == "__main__":
    solve()
```

---

## The Fundamentals Behind the Challenge

Understanding the underlying network and operating system mechanisms makes it clear why this bypass works.

### 1. TCP Streams and Input Buffering
In network applications, data sent over a TCP socket is not read byte-by-byte in real time by the application layer. Instead, the operating system kernel maintains a **receive buffer** for the socket. When data arrives from the network card, it is stored in this buffer. 

When a Python script calls `input()` or a socket read method, the system reads from this buffer. If data is already present, the function returns immediately. In `Lucky Dice`, because the server outputs the round details before checking the time, the client can process the data, calculate the answer, and send it back immediately. The answer sits in the server’s receive buffer. By the time the server starts its stopwatch and calls `input()`, the answer is already waiting, making the elapsed time negligible.

### 2. Time-of-Check to Time-of-Use (TOCTOU) / Timing Order
A secure timing check must encompass the entire window of user interaction. To prevent input buffering bypasses:
* The timer should start **before** any round details are printed to the client.
* Alternatively, non-blocking sockets or asynchronous polling (`select`/`poll` system calls) should be used to enforce a strict wall-clock timeout from the moment the data is sent.

### 3. Stable Sorting and Insertion Order (Tie-Breakers)
In Python, dictionaries preserve insertion order (from Python 3.7+). When the server uses `sorted()` on scores, it performs a stable sort. If two players have the identical highest score, the one inserted last retains its relative position and is declared the winner. To mimic this behavior in the solver, we must iterate sequentially and let subsequent identical maximum scores overwrite the previous winner selection.

---

## Vulnerability Summary

| Stage | Vulnerability / Design Flaw | Impact |
|-------|------------------------------|--------|
| **Timeout Bypass** | Timing check starts *after* printing round data and *only* during the `input()` call. | Complete bypass of the 0.3s response window. |
| **Logic Replication** | Stable sorting requirement for ties. | Failure to choose the correct winner on tie rounds if order is ignored. |

---

## Key Takeaways

1. **Place timing checks correctly:** When designing timed games or authentication challenges, start the timer before sending the prompt data, or enforce the deadline on the connection socket itself.
2. **Account for buffering:** Network input buffering will always allow clients to "pre-send" answers if prompts are predictable or sent before the timing begins.
3. **Handle tie-breakers explicitly:** Always verify the sorting stability or exact logic used by the target application when recreating state locally.
