import unittest
from dataclasses import replace

from tests._bootstrap import ensure_runtime_path

ensure_runtime_path()

from parallax_omega.receipts import ReceiptChain


class ReceiptTests(unittest.TestCase):
    def test_chain_valid(self):
        chain = ReceiptChain()
        chain.append("a", "ok", {"x": 1})
        chain.append("b", "ok", {"y": 2})
        self.assertTrue(chain.verify())

    def test_previous_hash_tamper_detected(self):
        chain = ReceiptChain()
        chain.append("a", "ok", {"x": 1})
        chain.append("b", "ok", {"y": 2})
        chain._receipts[1] = replace(chain._receipts[1], previous_hash="tampered")
        self.assertFalse(chain.verify())

    def test_payload_tamper_detected(self):
        chain = ReceiptChain()
        chain.append("a", "ok", {"x": 1})
        chain._receipts[0] = replace(chain._receipts[0], payload={"x": 999})
        self.assertFalse(chain.verify())

    def test_payload_hash_changes(self):
        first = ReceiptChain().append("a", "ok", {"x": 1})
        second = ReceiptChain().append("a", "ok", {"x": 2})
        self.assertNotEqual(first.payload_hash, second.payload_hash)

    def test_receipts_property_is_defensive_copy(self):
        chain = ReceiptChain()
        chain.append("a", "ok", {"x": 1})
        snapshot = list(chain.receipts)
        snapshot[0].payload["x"] = 7
        self.assertTrue(chain.verify())


if __name__ == "__main__":
    unittest.main()
