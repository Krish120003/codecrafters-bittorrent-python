import json
import sys
import hashlib


# import bencodepy - available if you need it!
import requests
import socket

# Examples:
#
# - decode_bencode(b"5:hello") -> b"hello"
# - decode_bencode(b"10:hello12345") -> b"hello12345"


from typing import Tuple


def parse_next_bencode(bs: bytes) -> Tuple[bytes, any]:
    identifier = chr(bs[0])

    # we have a string
    if identifier.isdigit():
        length = int(bs.split(b":")[0])
        # remove the length and the colon
        bs = bs[len(str(length)) + 1 :]
        value = bs[:length]
        leftover = bs[length:]

        return leftover, value

    # we have an integer
    elif identifier == "i":
        # find the first e
        value = bs[1 : bs.find(b"e")]
        leftover = bs[bs.find(b"e") + 1 :]

        return leftover, int(value)

    # we have a list
    elif identifier == "l":
        # strip the l
        bs = bs[1:]
        value = []

        while chr(bs[0]) != "e":
            bs, v = parse_next_bencode(bs)
            value.append(v)

        # strip the e
        bs = bs[1:]
        return bs, value

    # we have a dictionary
    elif identifier == "d":
        # strip the d
        bs = bs[1:]

        value = {}

        while chr(bs[0]) != "e":
            # get the key
            bs, k = parse_next_bencode(bs)
            # get the value
            bs, v = parse_next_bencode(bs)

            value[k.decode()] = v

        # strip the e
        bs = bs[1:]
        return bs, value

    raise NotImplementedError(f"Unknown identifier {identifier}")


def decode_bencode(bencoded_value):
    return parse_next_bencode(bencoded_value)[1]


def encode_bencode(value) -> bytes:
    res = b""
    if type(value) == str:
        res = f"{len(value)}:{value}".encode("utf-8")
    elif type(value) == bytes:
        res = f"{len(value)}:".encode("utf-8") + value
    elif type(value) == int:
        res = f"i{value}e".encode("utf-8")
    elif type(value) == list:
        res = "l".encode("utf-8")
        for v in value:
            res += encode_bencode(v)
        res += "e".encode("utf-8")

    elif type(value) == dict:
        res = "d".encode("utf-8")
        for key in sorted(value.keys()):
            res += encode_bencode(key)
            res += encode_bencode(value[key])
        res += "e".encode("utf-8")

    return res


def main():
    command = sys.argv[1]

    # # You can use print statements as follows for debugging, they'll be visible when running tests.
    # print("Logs from your program will appear here!")

    if command == "decode":
        bencoded_value = sys.argv[2].encode()

        # json.dumps() can't handle bytes, but bencoded "strings" need to be
        # bytestrings since they might contain non utf-8 characters.
        #
        # Let's convert them to strings for printing to the console.
        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode()

            raise TypeError(f"Type not serializable: {type(data)}")

        # Uncomment this block to pass the first stage
        print(json.dumps(decode_bencode(bencoded_value), default=bytes_to_str))

    elif command == "info":
        # ./your_bittorrent.sh info sample.torrent
        # read the torrent file
        with open(sys.argv[2], "rb") as f:
            torrent = f.read()
            # parse the torrent file
            torrent = decode_bencode(torrent)
            print("Tracker URL:", torrent["announce"].decode("utf-8"))
            print("Length:", torrent["info"]["length"])

            info_encoded = encode_bencode(torrent["info"])
            info_hash = hashlib.sha1(info_encoded).hexdigest()

            print("Info Hash:", info_hash)
            print("Piece Length:", torrent["info"]["piece length"])

            for i in range(0, len(torrent["info"]["pieces"]), 20):
                print(torrent["info"]["pieces"][i : i + 20].hex())

    elif command == "peers":
        # ./your_bittorrent.sh info sample.torrent
        # read the torrent file
        with open(sys.argv[2], "rb") as f:
            torrent = f.read()
            # parse the torrent file
            torrent = decode_bencode(torrent)

            url = torrent["announce"].decode("utf-8")

            info_encoded = encode_bencode(torrent["info"])

            res = requests.get(
                url,
                params={
                    "info_hash": hashlib.sha1(info_encoded).digest(),
                    "peer_id": "00112233445566778899",
                    "port": 6881,
                    "uploaded": 0,
                    "downloaded": 0,
                    "left": torrent["info"]["length"],
                    "compact": "1",
                },
            )

            response = decode_bencode(res.content)
            peers = response["peers"]

            for i in range(0, len(peers), 6):
                ip = ".".join(str(j) for j in peers[i : i + 4])
                port = int.from_bytes(peers[i + 4 : i + 6], byteorder="big")

                print(ip + ":" + str(port))

    elif command == "handshake":
        # ./your_bittorrent.sh info sample.torrent <peer_ip>:<peer_port>
        # read the torrent file
        with open(sys.argv[2], "rb") as f:
            torrent = f.read()
            # parse the torrent file
            torrent = decode_bencode(torrent)
            info_encoded = encode_bencode(torrent["info"])
            info_hash = hashlib.sha1(info_encoded).digest()

            peer_ip, peer_port = sys.argv[3].split(":")

            # create the handshake
            handshake = b"\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00"
            handshake += info_hash
            handshake += b"00112233445566778899"

            # connect to the peer
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((peer_ip, int(peer_port)))
            s.send(handshake)
            response_handshake = s.recv(len(handshake))

            # the last 20 bytes are the peer id
            peer_id = response_handshake[-20:]
            print("Peer ID:", peer_id.hex())

    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
