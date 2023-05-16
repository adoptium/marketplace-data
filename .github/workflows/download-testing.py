import argparse
import hashlib
import json
import os

import gnupg
import requests

exit_code = 0


def set_exit_code():
    global exit_code
    exit_code = exit_code + 1


def download_file(url, file_path):
    response = requests.get(url)
    with open(file_path, "wb") as file:
        file.write(response.content)


def validate_checksum(file_path, expected_checksum):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha256_hash.update(chunk)
    actual_checksum = sha256_hash.hexdigest()
    return actual_checksum == expected_checksum


def validate_signature(file_path, signature_url):
    gpg = gnupg.GPG()
    signature_file = file_path + ".sig"

    with open(signature_file, "wb") as file:
        signature_response = requests.get(signature_url)
        file.write(signature_response.content)

    with open(signature_file, "rb") as file:
        verified = gpg.verify_file(file, file_path)

    # delete the signature file
    os.remove(signature_file)

    return verified


def process_release(release):
    # check if release['binaries'] exists
    if "binaries" in release:
        for binary in release["binaries"]:
            package = binary["package"]
            process_package(package)

            # check if binary['installer'] exists
            if "installer" in binary:
                installers = binary["installer"]
                # loop through the installers list
                for installer in installers:
                    process_package(installer)


def process_package(package):
    download_file(package["link"], package["name"])
    expected_checksum = package["sha265sum"]
    checksum_link = package["sha256sum_link"]
    checksum_response = requests.get(checksum_link)
    checksum_link_value = checksum_response.text.strip()
    # ensure that expected checksum is in the checksum file
    assert expected_checksum in checksum_link_value, "sha256sum doesn't match the sum defined in the sha256sum_link file"
    is_checksum_valid = validate_checksum(package["name"], expected_checksum)

    if is_checksum_valid:
        print(f"Checksum is valid for {package['name']} ✅")
    else:
        set_exit_code()
        print(f"Checksum is NOT valid for {package['name']} ❌")

    # check if signature_link exists
    if "signature_link" in package:
        signature_link = package["signature_link"]
        is_signature_valid = validate_signature(package["name"], signature_link)

        if is_signature_valid:
            print(f"Signature is valid for {package['name']} ✅")
        else:
            set_exit_code()
            print(f"Signature is NOT valid for {package['name']} ❌")

    # delete the downloaded file
    os.remove(package["name"])


def process_json_file(json_file_path):
    with open(json_file_path) as json_file:
        data = json.load(json_file)
        releases = data["releases"]
        for release in releases:
            process_release(release)


parser = argparse.ArgumentParser(
    description="Download files and validate checksums/signatures."
)
parser.add_argument("file", help="JSON file containing the data")
args = parser.parse_args()

json_file_path = args.file
process_json_file(json_file_path)
exit(exit_code)
