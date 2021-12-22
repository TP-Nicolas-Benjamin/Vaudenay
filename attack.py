from posixpath import split
from urllib import request
from urllib.error import HTTPError, URLError
from Crypto.Util.Padding import unpad
import sys

PORT_NUMBER = 1234
BLOCK_SIZE = 16


def check(ciphertext: str):
    "check ciphertext by sending a request to the server"
    url = f"http://localhost:{PORT_NUMBER}/check"
    data = bytes('ciphertext=' + ciphertext.hex(), encoding="ASCII")
    req = request.Request(url, data, method="POST")
    try:
        resp = request.urlopen(req)
        code = resp.getcode()
    except HTTPError as e:
        code = e.getcode()
    except URLError as e:
        import sys
        print(f"** connection problem: {e}.")
        print(f"** Is the server running on port {PORT_NUMBER}?")
        sys.exit(2)
    assert code in (200, 599)
    return code


def del_padding(data: str) -> str:
    """
    del_padding : delete padding from data

    Args:
        data (str): data to delete padding

    Returns:
        str: data without padding
    """
    return unpad(data, BLOCK_SIZE, style='pkcs7')


def split_into_blocks(data: str) -> list:
    """
    split_into_blocks: split data into blocks

    Args:
        data (str): data to split

    Returns:
        list: list of blocks
    """
    return [data[i:i+BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]


def create_block() -> str:
    """
    create_block: create block with zero padding until index is reached then with correct padding

    Args:
        index (int): limit of zero value

    Returns:
        str: block with correct padding
    """
    return [0]*BLOCK_SIZE


def check_validity(ciphertext: str) -> bool:
    """
    check_validity: check if ciphertext is valid

    Args:
        ciphertext (str): ciphertext to check

    Returns:
        bool: True if valid, False otherwise
    """
    return check(ciphertext) == 200


def attack_block(block):

    # Init a 0 value vector
    zeroing_iv = create_block()
    # Start with a padding of 1 to 16
    for padding_value in range(1, BLOCK_SIZE + 1):
        # Calculate the padding each time with the previous padding
        iv_pad = [padding_value ^ b for b in zeroing_iv]
        # Testing the 256 possible values
        for value in range(256):
            iv_pad[-padding_value] = value
            # Asking the server to check the validity of the padding
            if check_validity(bytearray(iv_pad) + block):
                print(f"Value found {value} for padding value {padding_value}")
                break
        # Find the correct padding
        zeroing_iv[-padding_value] = value ^ padding_value
    return zeroing_iv


def crack_message(cyphered_blocks: bytearray) -> bytearray:
    # Add an empty block to the beginning of the cyphered blocks, like IV when using CBC
    cyphered_blocks = [bytearray(create_block())] + cyphered_blocks
    plain_text_b = b''

    initialization_vector = cyphered_blocks[0]
    # Iterate over the cyphered blocks
    for i in range(1, len(cyphered_blocks)):
        decrypted_block = attack_block(cyphered_blocks[i])
        plain_text_part = bytearray(initialization_vector ^ decrypted_block for initialization_vector,
                                    decrypted_block in zip(initialization_vector, decrypted_block))
        plain_text_b += plain_text_part
        # In CBC mode, the initialization vector for the next block is the current block
        initialization_vector = cyphered_blocks[i]
    # Delete the 1st block (IV)
    plain_text_b = plain_text_b[BLOCK_SIZE:]
    # Delete the padding
    plain_text_b = del_padding(plain_text_b)
    return plain_text_b


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("""Usage: python3 attack.py <ciphertext> 
In hexadecimal format.""")
        sys.exit(1)
    # From arg get the ciphertext
    ciphertext = sys.argv[1]
    B = bytearray.fromhex(ciphertext)
    cyphered_blocks = split_into_blocks(B)
    print(crack_message(cyphered_blocks))
