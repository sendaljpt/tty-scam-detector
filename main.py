import argparse
from detector import ScamDetector, banner

def main():
    banner()

    parser = argparse.ArgumentParser(
        description="Scam Link Detector 🔍"
    )

    parser.add_argument(
        "url",
        help="Masukkan URL yang ingin di scan"
    )

    args = parser.parse_args()

    scanner = ScamDetector(args.url)
    scanner.run_scan()


if __name__ == "__main__":
    main()