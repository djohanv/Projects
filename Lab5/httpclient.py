"""
- CCS2911 - 0NN
- Fall 2017
- Lab 5
- Names: Sagun Singh, Valerie Djohan
-
-

A simple HTTP client
"""

# import the "socket" module -- not using "from socket import *" in order to selectively use items with "socket." prefix
import socket

# import the "regular expressions" module
import re


def main():
    """
    Tests the client on a variety of resources
    """

    # These resource request should result in "Content-Length" data transfer
    # get_http_resource('http://msoe.us/taylor/images/taylor.jpg','taylor.jpg')

    get_http_resource('http://msoe.us/CS/cs1.1chart.png', 'chart.png')

    # this resource request should result in "chunked" data transfer
    get_http_resource('http://cdn.mathjax.org/mathjax/latest/MathJax.js', 'index.html')

    # If you find fun examples of chunked or Content-Length pages, please share them with us!
    get_http_resource('http://msoe.us/CS/', 'cs.html')  # for chunked decoding


def get_http_resource(url, file_name):
    """
    Get an HTTP resource from a server
           Parse the URL and call function to actually make the request.

    :param url: full URL of the resource to get
    :param file_name: name of file in which to store the retrieved resource

    (do not modify this function)
    """

    # Parse the URL into its component parts using a regular expression.
    url_match = re.search('http://([^/:]*)(:\d*)?(/.*)', url)
    url_match_groups = url_match.groups() if url_match else []
    #    print 'url_match_groups=',url_match_groups
    if len(url_match_groups) == 3:
        host_name = url_match_groups[0]
        host_port = int(url_match_groups[1][1:]) if url_match_groups[1] else 80
        host_resource = url_match_groups[2]
        print('host name = {0}, port = {1}, resource = {2}'.format(host_name, host_port, host_resource))
        status_string = make_http_request(host_name.encode(), host_port, host_resource.encode(), file_name)
        print('get_http_resource: URL="{0}", status="{1}"'.format(url, status_string))
    else:
        print('get_http_resource: URL parse failed, request not sent')


def make_http_request(host, port, resource, file_name):
    """
    Get an HTTP resource from a server

    :param bytes host: the ASCII domain name or IP address of the server machine (i.e., host) to connect to
    :param int port: port number to connect to on server host
    :param bytes resource: the ASCII path/name of resource to get. This is everything in the URL after the domain name,
           including the first /.
    :param file_name: string (str) containing name of file in which to store the retrieved resource
    :return: the status code
    :rtype: int
    """

    # make a connection with the server
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.connect((host, port))

    # this message is the response line:
    tcp_socket.sendall(send_message(resource.decode('ASCII'), host.decode('ASCII')))

    # to obtain the response length and get the source code:
    status_code = decode_status_line(tcp_socket)

    # To decode the payload
    message = payload_decoder(tcp_socket)

    # To save the file
    save_file(message, file_name)

    # Close the socket
    tcp_socket.close()

    return status_code  # Replace this "server error" with the actual status code


def send_message(resource, host):
    """
    Read the request line from the given URL
    The format of the request line is: GET/URL/HTTP/Version

    :param: resource: The URL given
    :param: host: The server host
    :return: the bytes of the request line
    """
    request = f'GET {resource} HTTP/1.1\r\n' \
              f'Host: {host}\r\n' \
              f'Connection: {"close"}\r\n' \
              f'Content-Length: {0}\r\n' \
              f'\r\n'
    message = request.encode('ASCII')
    # print(request)
    return message


def read_status_line(tcp_socket):
    """
    Helper method to read the response line in bytes
    Utilizes next_byte(tcp_socket)

    :param tcp_socket: the socket used by the client to connect to the server
    :return: bytes of the response line
    """
    response_bytes = next_byte(tcp_socket)

    while b'\r\n' not in response_bytes:
        response_bytes += next_byte(tcp_socket)

    return response_bytes


def decode_status_line(tcp_socket):
    """
    To obtain and decode the status code from the server's response that was obtained from
        read_status_line(tcp_socket)
    :param response: the URL of the file
    :param tcp_socket: the socket to connect to the server
    :return: int of the status code
    """
    # decode the response_message:
    decoded_message = ''
    new_item = b''

    response = read_status_line(tcp_socket)

    for item in response:
        new_item += item.to_bytes(1, 'big')

    decoded_message = new_item.decode('ASCII')
    print(decoded_message)
    # variables:
    list = []  # to store the message
    status_code = ''

    # use string.split('sp') to store the message
    list = decoded_message.split(' ')

    # list[1] is the status code
    status_code = list[1]

    # return and convert it to int
    return int(status_code)


def read_header(tcp_socket):
    """
    To read the header after the status code using next_byte(tcp_socket)

    :param tcp_socket: the tcp socket that was used to connect to the server
    :return: the header bytes
    """
    header_bytes = next_byte(tcp_socket)

    # to loop through the header until its the end of the header
    while b'\r\n\r\n' not in header_bytes:
        header_bytes += next_byte(tcp_socket)

    # return the header in bytes
    return header_bytes


def decode_header(tcp_socket):
    """
   The method to decode each byte of the header line
   :param response: the response message
   :return: string of the decoded header line
  """

    header_bytes = read_header(tcp_socket)
    decoded_header = header_bytes.decode('ASCII')
    # print(decoded_header)
    return decoded_header  # return the decoded header


def unparsed_header_contents(tcp_socket):
    """
    The contents from the decoded header
    Split by the "CRLF"
    And stored as a list
    :param response: the data obtained
    :return: the list of the contents
    """
    # get the message in one big line (in bytes)
    message_list = decode_header(tcp_socket)

    # split the message in the "\r\n" characters
    content_list = message_list.split("\r\n")
    return content_list  # return the list


def parsed_header(tcp_socket):
    """"
    To parse the list that contains the header information

    :param tcp_socket: the socket to connect to the server
    :return: dictionary that contains the header information
    """
    message_list = unparsed_header_contents(tcp_socket)
    header_dict = {}
    index = 0

    # split based on ": " and store it on a temporary list
    for items in message_list:
        tempList = items.split(": ")
        if items != "":
            header_dict[tempList[index]] = tempList[index + 1]

    return header_dict


def transfer_encoding_checker(header_dict):
    """
    To check if the header from the URL have Transfer-Encoding or not
        - If there is a Transfer-Encoding: Read the Message using Chunking Method
        - If there is no Transfer-Encoding: Read the Message based on it's Content-Length
    :param my_dict: the dictionary that stores the header information
    :return: boolean True / False
    """
    return "Transfer-Encoding" in header_dict


def read_payload_chunk_size(tcp_socket):
    """
    To read the message by chunks
    :param tcp_socket: the socket to connect to the server
    :return: bytes of size
    """
    payload_chunk_size = b''  # to store the bytes object

    payload_chunk_size = next_byte(tcp_socket)  # call next_bytes

    # continue calling the next_byte until it hits '\r\n' character
    while b'\r\n' not in payload_chunk_size:
        payload_chunk_size += next_byte(tcp_socket)

    # return the trimmed size version
    return payload_chunk_size[0:len(payload_chunk_size) - 2]


def decode_payload_chunk_size(tcp_socket):
    """
    To decode the payload's chunk size
    :param tcp_socket: The socket used to connect to the server
    :return: int of the size
    """
    # get the size in bytes
    size_in_hex = read_payload_chunk_size(tcp_socket).decode('ASCII')
    size = int(size_in_hex, 16)  # conver it to hex

    # return the size
    return size


def read_payload_by_chunk(chunk_size, tcp_socket):
    """
    To read the payload based on it's chunk size
    :param tcp_socket: The socket used to connect to the server
    :return:
    """
    # to store one chunk payload
    chunk_payload = b''

    # will continue calling next_byte according to the chunk_size
    for counter in range(chunk_size):
        chunk_payload += next_byte(tcp_socket)

    # return the chunk in bytes
    return chunk_payload


def read_all_chunks_in_payload(tcp_socket):
    """
    To read all chunk inside the payload
    :param tcp_socket: The server used to read all chunks in the payload
    :return:
    """
    chunk_size = decode_payload_chunk_size(tcp_socket)  # get the chunk_size
    payload_message = b''  # to store the bytes object

    while not chunk_size == 0:  # loop through until the chunk_size is 0
        payload_message += read_payload_by_chunk(chunk_size, tcp_socket)

        # to skip the CRLF Characters
        next_byte(tcp_socket)
        next_byte(tcp_socket)

        # reset the chunk_size
        chunk_size = decode_payload_chunk_size(tcp_socket)

    # return the payload from all chunks
    return payload_message


def decode_chunk_messages(tcp_socket):
    """
    To decode the messages obtained from the chunking method
    :param tcp_socket: The server used to read all chunks
    :return: the decoded message
    """
    # decode the message in ASCII
    message = read_all_chunks_in_payload(tcp_socket).decode('ASCII')
    # return the message
    return message


def get_content_length(header_dict):
    """
    To get the content-length inside the header dictionary
    :param header_dict: the dictionary that contains the header
    :return: int of content-length
    """
    # get the length from the header dictionary and convert it to int
    return int(header_dict.get("Content-Length"))


def read_payload_by_bytes(header_dict, tcp_socket):
    """
    To read the message in one big line
    :param tcp_socket: the socket to connect to the server
    :return: the message content in bytes
    """
    length = get_content_length(header_dict)  # get the content-length'
    # print(length)
    counter = 0  # a counter variable
    content_in_bytes = b""  # bytes variable to store the bytes

    # loop through the message according to the length and call next_byte
    while counter < length:
        content_in_bytes += next_byte(tcp_socket)
        counter += 1  # increment the counter by 1

    # return the payload in bytes
    return content_in_bytes


def decode_payload_content_bytes(header_dict, tcp_socket):
    """
    To decode the message
    :param tcp_socket:
    :return:
    """
    # store the payload in bytes
    payload_in_bytes = read_payload_by_bytes(header_dict, tcp_socket)

    # decode the payload:
    if b'\x00' not in payload_in_bytes:  # if it is not a raw binary, meaning it is a plain text
        payload = payload_in_bytes.decode('ASCII')

    else:
        return payload_in_bytes  # if it is a raw binary for the pictures
    return payload


def payload_decoder(tcp_socket):
    """
    The method that will call the content-length or chucking method
    :param tcp_socket: The socket to connect to the server
    :return: message
    """
    # store the header reference
    header_dict = parsed_header(tcp_socket)
    # check whether the trasfer-encoding is inside the header
    checker = transfer_encoding_checker(header_dict)
    message = ''  # variable for message

    # decide whether to use Chunking or Content-length
    if checker == True:
        print("Method: Chunking Method")
        # if get_transfer_encoding(header_dict) == 'chunked':
        message = decode_chunk_messages(tcp_socket)
    else:
        print("Method: Content-Length")
        message = decode_payload_content_bytes(header_dict, tcp_socket)
    # return the message
    return message


def save_file(message, output_filename):
    """
    Saves the decoded message to a new file


    Done by Valerie Djohan
    Used by Sagun Singh in read_message_content() method
    :param message: decoded message entered by author
    :return:
    """

    if '.png' in output_filename or '.jpg' in output_filename:
        with open(output_filename, "wb") as file_name:
            file_name.write(message)
    else:
        with open(output_filename, "w") as file_name:
            file_name.write(message)


def next_byte(tcp_socket):
    """
    (MODIFIED) next_byte() from Lab 4
    Read the next byte from the socket data_socket.

    Read the next byte from the sender, received over the network.
    If the byte has not yet arrived, this method blocks (waits)
      until the byte arrives.
    If the sender is done sending and is waiting for your response, this method blocks indefinitely.

    :param data_socket: The socket to read from. The data_socket argument should be an open tcp
                        data connection (either a client socket or a server data socket), not a tcp
                        server's listening socket.
    :return: the next byte, as a bytes object with a single byte in it
    """
    return tcp_socket.recv(1)


main()
