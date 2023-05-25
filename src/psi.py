import util
import ot
import yao
import pickle
from multiprocessing import Process
def _id(x, *args, **kwargs):
    return x
try: 
    from tqdm import tqdm
except ImportError:
    tqdm = _id


class Alice():
    """
    Alice creates garbled circuits and sends them to Bob, along with her
    encrypted outputs and the index of the value that Bob must use from 
    his set, for evaluation.
    
    Alice will generate and send at most n*m garbled circuits
    where n is the size of Alice's set, m of Bob's set.

    Attributes:
        socket  Alice's socket
        ot      Alice's side OT
        vals    a list containing the values in Alice's set
    """
    def __init__(self, vals, logger):
        self.socket = util.GarblerSocket()
        self.ot = ot.ObliviousTransfer(self.socket, logger, enabled=True)
        self.vals = sorted(vals)
        self.logger = logger

    """Send handshake message and wait for Bob to respond with the size of his set"""
    def setup(self):
        self.logger.info("Waiting for Bob")
        self.m = self.socket.send_wait(f"PSI") # size of Bob's set
        self.logger.info(f"Alice has {len(self.vals)} values, Bob has {self.m} values")
        self.logger.info("Starting PSI computation")

    """Run the PSI algorithm"""
    def run(self):
        """
        Always use the same circuit, sending Bob the index of the value
        to instantiate his bits on.
        (p-bits, keys and consequently the garbled tables are freshly
        generated each time, to avoid security flaws)
        """
        circuit = util.parse_json("circuits/eq32.json")["circuits"][0]
        matched = []
        exclude = []
        for i in tqdm(range(len(self.vals)), desc="Progress"):
            for j in range(self.m):
                # don't run Yao if one of the values is already in the intersection
                if (self.vals[i] in matched) or (j in exclude):
                    continue

                # create the circuit and populate the dict to send to Bob
                garbled_circuit = yao.GarbledCircuit(circuit)
                self.logger.circuit(str(garbled_circuit))
                pbits = garbled_circuit.get_pbits()
                entry = {
                    "circuit": circuit,
                    "garbled_circuit": garbled_circuit,
                    "garbled_tables": garbled_circuit.get_garbled_tables(),
                    "keys": garbled_circuit.get_keys(),
                    "pbits": pbits,
                    "pbits_out": {w: pbits[w]
                              for w in circuit["out"]},
                }

                to_send = {
                    "j": j, # index of the value which Bob should use to evaluate the circuit
                    "circuit": entry["circuit"],
                    "garbled_tables": entry["garbled_tables"],
                    "pbits_out": entry["pbits_out"],
                }
                self.socket.send_wait(to_send)

                # set Alice's bits to the ones of the value at index i in her set
                bits_a = util.float_to_bit_list(self.vals[i])
                # send Alice's input bits' keys, make Bob evaluate the circuit and receive the result
                res = self.eval_single(entry, bits_a)

                # extract the result bit and turn it into a Boolean
                match = bool(res[list(res.keys())[0]])

                if match:
                    matched.append(self.vals[i])
                    exclude.append(j)

        self.logger.info("PSI computation ended")
        self.logger.minimal("{" + str(matched)[1:][:-1] + "}")
        self.socket.send_wait("OK") # tell Bob that the computation is over
        return matched
            
    """Evaluate a circuit with the given values for Alice's bits"""
    def eval_single(self, entry, bits_a):
        circuit, pbits, keys = entry["circuit"], entry["pbits"], entry["keys"]
        outputs = circuit["out"]
        a_wires = circuit.get("alice", [])  # Alice's wires
        a_inputs = {}  # map from Alice's wires to (key, encr_bit) inputs
        b_wires = circuit.get("bob", [])  # Bob's wires
        b_keys = {  # map from Bob's wires to a pair (key, encr_bit)
            w: self._get_encr_bits(pbits[w], key0, key1)
            for w, (key0, key1) in keys.items() if w in b_wires
        }

        for i in range(len(a_wires)):
            a_inputs[a_wires[i]] = (keys[a_wires[i]][bits_a[i]],
                                    pbits[a_wires[i]] ^ bits_a[i])
        result = self.ot.get_result(a_inputs, b_keys)
        return result

    def _get_encr_bits(self, pbit, key0, key1):
        return ((key0, 0 ^ pbit), (key1, 1 ^ pbit))


class Bob:
    """
    Bob receives circuits along with the index of the value from his set 
    to be used for the computation, and sends the results back to Alice.

    Attributes:
        socket  Bob's socket
        ot      Bob's side OT
        vals    a list containing the values in Bob's set
        matched a list that will store the values that are in the intersection
    """
    def __init__(self, vals, logger):
        self.socket = util.EvaluatorSocket()
        self.ot = ot.ObliviousTransfer(self.socket, logger, enabled=True)
        self.vals = sorted(vals)
        self.logger = logger
        self.matched = []

    """
    Wait for the handshake message and respond with the size of Bob's set.
    Then, evaluate the individual circuits and send back the results.
    """
    def listen(self):
        try:
            self.logger.info(f"Waiting for Alice")
            m = self.socket.receive()
            if m == "PSI":
                self.logger.info(f"Starting PSI computation")
                self.socket.send(len(self.vals))
                m = self.socket.receive()
                while m != "OK":
                    self.socket.send(True)
                    self.eval_single(m)
                    m = self.socket.receive()
                self.socket.send(True)
                self.logger.info("PSI computation ended")
                self.logger.minimal("{" + str(self.matched)[1:][:-1] + "}")
                return self.matched
            else:
                raise RuntimeError(f"Unrecognized message {m}")
        except KeyboardInterrupt:
            self.logger.info("Aborted")

    """
    Evaluate a circuit setting Bob's bits to the ones corresponding to
    the value at the requested index in Bob's set
    """
    def eval_single(self, entry):
        circuit, pbits_out = entry["circuit"], entry["pbits_out"]
        garbled_tables = entry["garbled_tables"]
        a_wires = circuit.get("alice", [])  # list of Alice's wires
        b_wires = circuit.get("bob", [])  # list of Bob's wires

        bits_b = util.float_to_bit_list(self.vals[entry["j"]])
        b_inputs_clear = {
            b_wires[i]: bits_b[i]
            for i in range(len(b_wires))
        }

        res = self.ot.send_result(circuit, garbled_tables, pbits_out, b_inputs_clear)
        res = bool(list(res.values())[0])
        if res:
            self.matched.append(self.vals[entry["j"]])


def psi(party, vals, output_mode):

    if output_mode == "minimal":
        global tqdm
        tqdm = _id

    def run_alice(vals, logger):
        alice = Alice(vals, logger)
        alice.setup()
        return alice.run()

    def run_bob(vals, logger):
        bob = Bob(vals, logger)
        return bob.listen()

    def run_test(vals, logger_a, logger_b, logger):
        if len(vals) != 2:
            raise RuntimeError("You need to specify both sets when using test mode, e.g. python3.8 psi.py \"{1.2,2.5}\" \"{1.2,4.3}\"")
        bob = Process(target=run_bob, args=(vals[1], logger_b))
        e = bob.start()
        result = run_alice(vals[0], logger_a)
        v = bob.join()
        intersection = sorted([a for a in vals[0] if a in vals[1]])
        logger.info(f"Result computed without using Yao's protocol: {'{' + str(intersection)[1:][:-1] + '}'}")
        if set(result) == set(intersection):
            logger.info("Result is correct!")
        else:
            logger.info("Result is wrong!")

    if party == "alice":
        run_alice(vals[0], util.Logger("Alice", output_mode))
    elif party == "bob":
        run_bob(vals[0], util.Logger("Bob", output_mode))
    elif party == "test":
        run_test(vals, 
            util.Logger("Alice", output_mode, prepend="[Alice] "), 
            util.Logger("Bob", output_mode, prepend="[Bob] "),
            util.Logger("test", output_mode, prepend="[-] ")
        )
    else:
        raise RuntimeError(f"Unknown party {party}. Possible values: alice, bob, test.")


if __name__ == '__main__':
    import argparse

    def init():
        output_modes = ["minimal", "info", "full"]

        parser = argparse.ArgumentParser(
            description="Compute the intersection of sets held by two parties using a protocol based on Yao's garbled circuits.\n" +
                        "Supports sets of 32-bit floats.",
            formatter_class=argparse.RawTextHelpFormatter
        )
        
        parser.add_argument("party",
            choices=["alice", "bob", "test"],
            help="the yao party to run\n" +
                 "test runs both parties using a child process for Bob"
        )
        parser.add_argument("set",
            help="the party's set enclosed in braces and quotation marks\n" +
                 "e.g. \"{1.21, 10.88, 12.66e4, math.pi}\"\n" +
                 "if you are using test mode you need to specify two sets separated by a space\n" +
                 "e.g. \"{1.3, 10.8}\" \"{8.4, 2.22}\"",
            type=util.parse_float_set,
            nargs="*"
        )
        parser.add_argument("-o", 
            dest="output_mode",
            choices=output_modes,
            default="info",
            help="the output mode:\n" + 
                 "\tminimal\t only prints the result followed by \\n\n" + 
                 "\tinfo\t shows additional information about what the party is doing and a progress bar (default)\n" + 
                 "\tfull\t also outputs information about the OT in the files ot_Alice.txt, ot_Bob.txt and the garbled tables in tables.txt in the output folder\n"
        )
        psi(party=parser.parse_args().party,
            vals=parser.parse_args().set,
            output_mode=parser.parse_args().output_mode
        )

    init()