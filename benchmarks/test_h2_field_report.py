import copy
import unittest

from h2_field_report import validate_report


def report():
    # Two 32-byte field blocks, two 50-byte responses, a 21-byte server
    # SETTINGS, its 9-byte ACK, a 17-byte PING ACK, and one HPACK update byte.
    return dict(requests=2, errors=0, block_bytes=32, chunk=65536,
                connections=1, pipeline=1, elapsed_seconds=1, rps=2,
                sent_bytes=147, received_bytes=148, application_writes=6,
                latencies_ns=[100, 200], peers=[dict(
                    id=0, requests=2, samples=2, last_stream=3, field_bytes=64,
                    sent_bytes=147, received_bytes=148, application_writes=6,
                    credit_updates=0, returned_credit=0)])


class ResponseAccounting(unittest.TestCase):
    def validate(self, value):
        validate_report(value, 32, 65536, 2, 1, 1)

    def test_size_update_is_counted_once_per_connection(self):
        self.validate(report())

    def test_omitted_or_extra_update_byte_cannot_be_hidden_in_totals(self):
        for delta in [-1, 1]:
            value = report()
            value["received_bytes"] += delta
            value["peers"][0]["received_bytes"] += delta
            with self.subTest(delta=delta), self.assertRaises(AssertionError):
                self.validate(value)

    def test_worker_and_aggregate_received_bytes_must_agree(self):
        value = report()
        value["peers"][0]["received_bytes"] -= 1
        with self.assertRaises(AssertionError):
            self.validate(value)
        value = report()
        value["received_bytes"] -= 1
        with self.assertRaises(AssertionError):
            self.validate(value)

    def test_wire_update_does_not_count_as_a_response_or_sample(self):
        for field in ["requests", "samples"]:
            value = report()
            value["peers"][0][field] += 1
            with self.subTest(field=field), self.assertRaises(AssertionError):
                self.validate(value)
        for samples in [[100], [100, 200, 300]]:
            value = copy.deepcopy(report())
            value["latencies_ns"] = samples
            with self.subTest(samples=samples), self.assertRaises(AssertionError):
                self.validate(value)


if __name__ == "__main__":
    unittest.main()
