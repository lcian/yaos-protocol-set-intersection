# Introduction to Cybersecurity

This repository contains my project for the course of "Introduction to Cybersecurity" at the University of Klagenfurt.

The project is an implementation of a protocol for the computation of Private Set Intersection by leveraging [Yao's protocol](https://ieeexplore.ieee.org/document/4568207). You can read the report [here](report.pdf), where I explain the set intersection algorithm, the circuit I used and how to run the code.

The code for Yao's protocol is due to Olivier Roques and Emmanuelle Risson, and was taken from [this repository](https://github.com/ojroques/garbled-circuit).
I modified the source code to include the [free-XOR optimization](http://www.cs.toronto.edu/~vlad/papers/XOR_ICALP08.pdf) of the protocol, which greatly speeds up computation with this particular circuit.
