import unittest
import sys
import os

# Add the parent directory to the path so we can import the core modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.checker import checker


class TestChecker(unittest.TestCase):

    def test_checker_function_exists(self):
        """Test that the checker function exists and is callable."""
        self.assertTrue(callable(checker))

    def test_checker_parameters(self):
        """Test that the checker function accepts correct number of parameters."""
        # This test just verifies the function signature
        # In a real implementation, we would mock the requester and test actual functionality
        try:
            # This will likely fail due to network calls, but tests the parameter signature
            result = checker("http://example.com", {}, {}, True, 0, "test", [], 5, None)
            # If it doesn't raise a TypeError, the signature is correct
        except (TypeError, AttributeError) as e:
            # If TypeError is about number of arguments, that's what we're testing
            if "takes" in str(e) and "positional argument" in str(e):
                self.fail(f"Checker function signature error: {e}")
        except:
            # Other exceptions are expected due to actual network operations
            pass


if __name__ == "__main__":
    unittest.main()
