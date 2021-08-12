from typing import Optional

from bcc import libbcc

import ctypes
import unittest


class XdpUnitTestBase(unittest.TestCase):

    SKB_OUT_SIZE = 1514  # suppose mtu = 1500, and extra 14 ethernet headers.
    bpf_function = None

    def _xdp_test_run(self,
                      given: bytes,
                      expected: Optional[bytes],
                      ret_val: int,
                      repeat: int = 1,
                      failing_duration: int = -1,
                      ) -> None:
        """
        :param given: input packet of the xdp program
        :param expected: expected output of the xdp program
        :param ret_val: expected return code
        :param repeat: times to repeat the test
        :param failing_duration: if program does not finish in time, fails the test
        """

        libbcc.lib.bpf_prog_test_run()
        given_packet_len = len(given)
        ctyped_given_packet = ctypes.create_string_buffer(given, given_packet_len)
        output_packet_buffer = ctypes.create_string_buffer(self.SKB_OUT_SIZE)
        output_packet_size = ctypes.c_uint32()

        actual_ret_val = ctypes.c_uint32()
        duration = ctypes.c_uint32()

        ret = libbcc.lib.bpf_prog_test_run(
            self.bpf_function.fd,
            repeat,
            ctypes.byref(ctyped_given_packet),
            given_packet_len,
            ctypes.byref(output_packet_buffer),
            ctypes.byref(output_packet_size),
            ctypes.byref(actual_ret_val),
            ctypes.byref(duration),
        )

        self.assertEqual(ret, 0)
        self.assertEqual(actual_ret_val.value, ret_val)
        if expected:
            self.assertEqual(
                output_packet_buffer[0:output_packet_size.value],
                expected
            )
        if failing_duration > 0:
            self.assertLess(duration, failing_duration)


