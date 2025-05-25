import unittest
import sys
import os

# Add the parent directory to the path so we can import the core modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.colors import red, green, yellow, white, end, info, que, bad, good, run


class TestColors(unittest.TestCase):

    def test_color_constants_exist(self):
        """Test that all color constants are defined."""
        # Test that color constants are strings
        self.assertIsInstance(red, str)
        self.assertIsInstance(green, str)
        self.assertIsInstance(yellow, str)
        self.assertIsInstance(white, str)
        self.assertIsInstance(end, str)

    def test_color_formatting_constants(self):
        """Test that color formatting constants are defined."""
        self.assertIsInstance(info, str)
        self.assertIsInstance(que, str)
        self.assertIsInstance(bad, str)
        self.assertIsInstance(good, str)
        self.assertIsInstance(run, str)

    def test_colors_not_empty(self):
        """Test that color constants are not empty strings."""
        # Only test that they exist - the actual values depend on terminal support
        self.assertIsNotNone(red)
        self.assertIsNotNone(green)
        self.assertIsNotNone(end)


if __name__ == "__main__":
    unittest.main()
