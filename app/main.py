import json
import sys

# import bencodepy - available if you need it!
# import requests - available if you need it!


# Examples:
#
# - decode_bencode(b"5:hello") -> b"hello"
# - decode_bencode(b"10:hello12345") -> b"hello12345"


def parse_next_bencode(bs: str) -> (str, any):
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


def decode_bencode(bencoded_value):
    return parse_next_bencode(bencoded_value)[1]
    if chr(bencoded_value[0]).isdigit():
        length = int(bencoded_value.split(b":")[0])
        return bencoded_value.split(b":")[1][:length]
    elif chr(bencoded_value[0]) == "i":
        return int(bencoded_value[1:-1])
    elif chr(bencoded_value[0]) == "l":
        leftover = bencoded_value[1:-1]
        result = []

        while leftover:
            if chr(leftover[0]).isdigit():
                length = int(leftover.split(b":")[0])
                result.append(leftover.split(b":")[1][:length])
                leftover = leftover.split(b":")[1][length:]
            elif chr(leftover[0]) == "i":
                result.append(int(leftover[1:].split(b"e")[0]))
                leftover = leftover[1:].split(b"e")[1]

        return result
    else:
        raise NotImplementedError("Only strings are supported at the moment")


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
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
