# 🔒 Yao's protocol – set intersection

Yao's protocol – set intersection is a proof of concept implementation for the secure multi-party computation of set intersection.
 
The implementation is based on [Yao's protocol](https://ieeexplore.ieee.org/document/4568207) (aka garbled circuits), one of the first protocols for secure multi-party computation.

Its Python implementation is taken from [this repository](https://github.com/ojroques/garbled-circuit), which I modified to implement the [free-XOR optimization](http://www.cs.toronto.edu/~vlad/papers/XOR_ICALP08.pdf), a variant that makes the computation much more efficient for this particular function.

You can read the full report [here](report.pdf), where I describe my choices for the implementation as well as instructions on how to run the code.
