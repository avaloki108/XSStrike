import unittest
import sys
import os

# Add the parent directory to the path so we can import the core modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.utils import counter, stripper, randomUpper, extractHeaders


class TestUtils(unittest.TestCase):

    def test_counter(self):
        """Test the counter function which counts non-alphanumeric characters."""
        self.assertEqual(counter("abc123"), 0)
        self.assertEqual(counter("abc!@#"), 3)
        self.assertEqual(counter("!@#$%^"), 6)
        self.assertEqual(counter(""), 0)

    def test_stripper(self):
        """Test the stripper function which removes the first occurrence of a substring from a string."""
        # Test right direction (default)
        self.assertEqual(stripper("abcdef", "c"), "abdef")
        self.assertEqual(stripper("abcdef", "z"), "abcdef")

        # Test left direction
        self.assertEqual(stripper("abcdef", "c", "left"), "abdef")
        self.assertEqual(stripper("abcdef", "z", "left"), "abcdef")

    def test_randomUpper(self):
        """Test that randomUpper returns a string of the same length."""
        test_str = "abcdefghijklmnopqrstuvwxyz"
        result = randomUpper(test_str)

        # Check that the length is the same
        self.assertEqual(len(test_str), len(result))

        # Check that the result is not the same as the original (this could fail rarely due to randomness)
        self.assertNotEqual(test_str, result)

        # Check that the result is the same as the original when lowercased
        self.assertEqual(test_str, result.lower())

    def test_extractHeaders(self):
        """Test the extractHeaders function which extracts headers from a string."""
        headers_str = (
            "Content-Type: application/json\nUser-Agent: Mozilla/5.0\nAccept: */*"
        )
        expected = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0",
            "Accept": "*/*",
        }
        self.assertEqual(extractHeaders(headers_str), expected)

        # Test with trailing comma
        headers_str = (
            "Content-Type: application/json,\nUser-Agent: Mozilla/5.0\nAccept: */*"
        )
        self.assertEqual(extractHeaders(headers_str), expected)


if __name__ == "__main__":
    unittest.main()
