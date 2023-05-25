import hashlib
import pickle
import util
import yao


class ObliviousTransfer:
    def __init__(self, socket, logger, enabled=True):
        self.socket = socket
        self.enabled = enabled
        self.logger = logger

    def get_result(self, a_inputs, b_keys):
        """Send Alice's inputs and retrieve Bob's result of evaluation.

        Args:
            a_inputs: A dict mapping Alice's wires to (key, encr_bit) inputs.
            b_keys: A dict mapping each Bob's wire to a pair (key, encr_bit).

        Returns:
            The result of the yao circuit evaluation.
        """
        self.logger.ot("Sending my input keys to Bob")
        self.socket.send(a_inputs)

        for _ in range(len(b_keys)):
            w = self.socket.receive()  # receive wire ID where to perform OT
            self.logger.ot("\n")
            self.logger.ot(f"Received wire ID {w}")

            if self.enabled:  # perform oblivious transfer
                pair = (pickle.dumps(b_keys[w][0]), pickle.dumps(b_keys[w][1]))
                self.ot_garbler(pair)
            else:
                to_send = (b_keys[w][0], b_keys[w][1])
                self.socket.send(to_send)

        self.logger.ot("\n" + "="*120)
        a = self.socket.receive()
        return a

    def send_result(self, circuit, g_tables, pbits_out, b_inputs):
        """Evaluate circuit and send the result to Alice.

        Args:
            circuit: A dict containing circuit spec.
            g_tables: Garbled tables of yao circuit.
            pbits_out: p-bits of outputs.
            b_inputs: A dict mapping Bob's wires to (clear) input bits.
        """
        # map from Alice's wires to (key, encr_bit) inputs
        a_inputs = self.socket.receive()
        # map from Bob's wires to (key, encr_bit) inputs
        b_inputs_encr = {}

        self.logger.ot("Received Alice's input keys")

        for w, b_input in b_inputs.items():
            self.logger.ot("\n")
            self.logger.ot(f"Sending wire ID {w}")
            self.socket.send(w)

            if self.enabled:
                b_inputs_encr[w] = pickle.loads(self.ot_evaluator(b_input))
                self.logger.ot(f"Received key {b_inputs_encr[w]}")
            else:
                pair = self.socket.receive()
                b_inputs_encr[w] = pair[b_input]

        result = yao.evaluate(circuit, g_tables, pbits_out, a_inputs,
                              b_inputs_encr)

        self.logger.ot(f"\nSending circuit evaluation {result}")
        self.logger.ot("\n" + "="*120)
        self.socket.send(result)
        return result

    def ot_garbler(self, msgs):
        """Oblivious transfer, Alice's side.

        Args:
            msgs: A pair (msg1, msg2) to suggest to Bob.
        """
        self.logger.ot("OT protocol started")
        self.logger.ot(f"m_0 = {msgs[0].hex()}")
        self.logger.ot(f"m_1 = {msgs[1].hex()}")
        G = util.PrimeGroup()
        self.socket.send_wait(G)
        self.logger.ot(f"Using G = {G}")

        # OT protocol based on Nigel Smart’s "Cryptography Made Simple"
        c = G.gen_pow(G.rand_int())
        h0 = self.socket.send_wait(c)
        self.logger.ot(f"Sent c = {c}")
        self.logger.ot(f"Received h_0 = {h0}")
        h1 = G.mul(c, G.inv(h0))
        self.logger.ot("Computing h_1 = c * h_0^{-1} = " + str(h1))
        k = G.rand_int()
        c1 = G.gen_pow(k)
        self.logger.ot(f"Encrypting with k = {k}")
        e0 = util.xor_bytes(msgs[0], self.ot_hash(G.pow(h0, k), len(msgs[0])))
        e1 = util.xor_bytes(msgs[1], self.ot_hash(G.pow(h1, k), len(msgs[1])))
        self.logger.ot("Sending")
        self.logger.ot(f"e_0 = {e0.hex()}")
        self.logger.ot(f"e_1 = {e1.hex()}")

        self.socket.send((c1, e0, e1))
        self.logger.ot("OT protocol ended")

    def ot_evaluator(self, b):
        """Oblivious transfer, Bob's side.

        Args:
            b: Bob's input bit used to select one of Alice's messages.

        Returns:
            The message selected by Bob.
        """
        self.logger.ot("OT protocol started")
        G = self.socket.receive()
        self.logger.ot(f"Received G = {G}")
        self.socket.send(True)

        # OT protocol based on Nigel Smart’s "Cryptography Made Simple"
        c = self.socket.receive()
        self.logger.ot(f"Received c = {c}")
        x = G.rand_int()
        self.logger.ot(f"Using x = {x}")
        x_pow = G.gen_pow(x)
        h = (x_pow, G.mul(c, G.inv(x_pow)))
        c1, e0, e1 = self.socket.send_wait(h[b])
        self.logger.ot(f"Sent h_{b} = {h[b]}")
        e = (e0, e1)
        self.logger.ot(f"Received")
        self.logger.ot(f"c_1 = {c1}")
        self.logger.ot(f"e_0 = {e0.hex()}")
        self.logger.ot(f"e_1 = {e1.hex()}")
        ot_hash = self.ot_hash(G.pow(c1, x), len(e[b]))
        mb = util.xor_bytes(e[b], ot_hash)
        self.logger.ot(f"Computed m_{b} = {mb.hex()}")

        self.logger.ot("OT protocol ended")
        return mb

    @staticmethod
    def ot_hash(pub_key, msg_length):
        """Hash function for OT keys."""
        key_length = (pub_key.bit_length() + 7) // 8  # key length in bytes
        bytes = pub_key.to_bytes(key_length, byteorder="big")
        return hashlib.shake_256(bytes).digest(msg_length)
