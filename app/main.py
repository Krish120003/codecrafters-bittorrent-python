import json
import sys
import hashlib
import math


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


def get_peers(torrent):
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
    peers_raw = response["peers"]

    peers = []

    for i in range(0, len(peers_raw), 6):
        ip = ".".join(str(j) for j in peers_raw[i : i + 4])
        port = int.from_bytes(peers_raw[i + 4 : i + 6], byteorder="big")
        peers.append(ip + ":" + str(port))

    return peers


def generate_handshake(torrent):
    info_encoded = encode_bencode(torrent["info"])
    info_hash = hashlib.sha1(info_encoded).digest()

    # create the handshake
    handshake = b"\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00"
    handshake += info_hash
    handshake += b"00112233445566778899"
    return handshake


def do_handshake(torrent, peer_ip, peer_port):
    handshake = generate_handshake(torrent)

    # connect to the peer
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((peer_ip, int(peer_port)))
        s.send(handshake)
        response_handshake = s.recv(len(handshake))

    return response_handshake


def download_single_piece(torrent_file, piece_index, output_file):
    # read the torrent to get the file tracker url
    with open(torrent_file, "rb") as f:
        torrent = f.read()
        # parse the torrent file
        torrent = decode_bencode(torrent)

    # get the peers
    peers = get_peers(torrent)
    peer = peers[1]  # we just use the first peer
    peer_ip, peer_port = peer.split(":")

    # connect to the peer
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print("Connecting to peer", peer_ip, peer_port)
        s.connect((peer_ip, int(peer_port)))
        # send the handshake
        handshake = generate_handshake(torrent)
        s.sendall(handshake)
        # receive the handshake
        response_handshake = s.recv(len(handshake))

        # we must wait for the bitfield message
        # the bitfield message is the first message after the handshake
        length, msg_type = s.recv(4), s.recv(1)
        if msg_type != b"\x05":
            raise Exception("Expected bitfield message")

        # read the bitfield
        # we subtract 1 because the length includes the type
        s.recv(int.from_bytes(length, byteorder="big") - 1)  # read the bitfield

        s.sendall(b"\x00\x00\x00\x01\x02")  # 1 length, 2 type (interested)

        # we must wait for the unchoke message
        length, msg_type = s.recv(4), s.recv(1)

        while msg_type != b"\x01":  # wait for unchoke
            length, msg_type = s.recv(4), s.recv(1)

        # we are now unchoked

        piece = download_piece(piece_index, torrent, s)

        with open(output_file, "wb") as f:
            f.write(piece)


def download_piece(piece_index, torrent, s):
    piece_length = torrent["info"]["piece length"]
    # however, the last piece might be shorter
    # so we need to check if this is the last piece
    chuck_size = 16 * 1024

    if piece_index == (len(torrent["info"]["pieces"]) // 20) - 1:
        piece_length = (
            torrent["info"]["length"] % piece_length
        )  # we can mod to find the remainder

    piece = b""

    for i in range(math.ceil(piece_length / chuck_size)):
        msg_id = b"\x06"
        chunk_index = piece_index.to_bytes(4)
        chunk_begin = (i * chuck_size).to_bytes(4)

        # if this is the last chunk, we need to get the remainder
        if (
            i == math.ceil((piece_length / chuck_size)) - 1
            and piece_length % chuck_size != 0
        ):
            chunk_length = piece_length % chuck_size
        else:
            chunk_length = chuck_size

        chunk_length = chunk_length.to_bytes(4)

        print("Requesting", chunk_index, chunk_begin, chunk_length)

        msg = msg_id + chunk_index + chunk_begin + chunk_length
        msg = len(msg).to_bytes(4) + msg

        s.sendall(msg)

        # wait for the piece
        length, msg_type = int.from_bytes(s.recv(4)), s.recv(1)

        # assert msg_type == b"\x07"

        # now we are getting the payload
        resp_index = int.from_bytes(s.recv(4))
        resp_begin = int.from_bytes(s.recv(4))

        block = b""
        to_get = int.from_bytes(chunk_length)
        while len(block) < to_get:
            block += s.recv(to_get - len(block))

        piece += block

    og_hash = torrent["info"]["pieces"][piece_index * 20 : piece_index * 20 + 20]
    assert hashlib.sha1(piece).digest() == og_hash
    return piece


def download_file(torrent_file, output_file):
    # read the torrent to get the file tracker url
    with open(torrent_file, "rb") as f:
        torrent = f.read()
        # parse the torrent file
        torrent = decode_bencode(torrent)

    # get the peers
    peers = get_peers(torrent)
    peer = peers[1]  # we just use the first peer
    peer_ip, peer_port = peer.split(":")

    # connect to the peer
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print("Connecting to peer", peer_ip, peer_port)
        s.connect((peer_ip, int(peer_port)))

        # send the handshake
        handshake = generate_handshake(torrent)
        s.sendall(handshake)
        # receive the handshake
        response_handshake = s.recv(len(handshake))

        # we must wait for the bitfield message
        # the bitfield message is the first message after the handshake
        length, msg_type = s.recv(4), s.recv(1)
        if msg_type != b"\x05":
            raise Exception("Expected bitfield message")

        # read the bitfield
        # we subtract 1 because the length includes the type
        s.recv(int.from_bytes(length, byteorder="big") - 1)  # read the bitfield

        s.sendall(b"\x00\x00\x00\x01\x02")  # 1 length, 2 type (interested)

        # we must wait for the unchoke message
        length, msg_type = s.recv(4), s.recv(1)

        while msg_type != b"\x01":  # wait for unchoke
            length, msg_type = s.recv(4), s.recv(1)

        # we are now unchoked

        # now we just download every piece
        data = b""
        for i in range(len(torrent["info"]["pieces"]) // 20):
            piece = download_piece(i, torrent, s)
            data += piece

        with open(output_file, "wb") as f:
            f.write(data)


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

            peers = get_peers(torrent)
            print(*peers, sep="\n")

    elif command == "handshake":
        # ./your_bittorrent.sh info sample.torrent <peer_ip>:<peer_port>
        # read the torrent file
        with open(sys.argv[2], "rb") as f:
            torrent = f.read()
            # parse the torrent file
            torrent = decode_bencode(torrent)

            peer_ip, peer_port = sys.argv[3].split(":")
            response_handshake = do_handshake(torrent, peer_ip, peer_port)

            # the last 20 bytes are the peer id
            peer_id = response_handshake[-20:]
            print("Peer ID:", peer_id.hex())

    elif command == "download_piece":
        #  ./your_bittorrent.sh download_piece -o /tmp/test-piece-0 sample.torrent 0

        output_file = sys.argv[3]
        torrent_file = sys.argv[4]
        piece_index = int(sys.argv[5])

        download_single_piece(torrent_file, piece_index, output_file)

    elif command == "download":
        # ./your_bittorrent.sh download -o /tmp/test.txt sample.torrent

        output_file = sys.argv[3]
        torrent_file = sys.argv[4]

        download_file(torrent_file, output_file)

    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
