import unittest
from app.services.jobs import parse_targets

class ParseTargetsTests(unittest.TestCase):
    def test_duplicates_and_sorting(self):
        self.assertEqual(parse_targets('192.168.1.10\n192.168.1.2\n192.168.1.2'), ['192.168.1.2', '192.168.1.10'])

    def test_inventory_csv(self):
        self.assertEqual(parse_targets('IP,System Name,Serial Number,Model\n192.168.1.3,SW-1,CN123,JL681A'), ['192.168.1.3'])

    def test_range(self):
        self.assertEqual(parse_targets('192.168.1.1-192.168.1.3'), ['192.168.1.1','192.168.1.2','192.168.1.3'])

    def test_invalid(self):
        with self.assertRaises(ValueError): parse_targets('not a valid host!')

if __name__ == '__main__': unittest.main()
