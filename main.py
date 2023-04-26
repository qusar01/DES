import DesTables as dt
import tkinter as tk
import random
import base64

def generate_key():
    key = ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=8))
    key_entry.delete(0, tk.END)
    key_entry.insert(0, key)
    return key

def loadKey():
    try:
        with open(loadKey_entry.get(), "r") as file:
            key = file.read()
            if len(key) == 8:
                key_entry.delete(0, tk.END)
                key_entry.insert(0, key)
                file.close()
            else:
                print("Key has wrong length")
                file.close()
    except FileNotFoundError:
        print("File doesn't exist")

def saveKey():
    try:
        with open(saveKey_entry.get(), "w") as file:
            if len(key_entry.get()) == 8:
                key = key_entry.get()
                file.write(key)
                file.close()
            else:
                print("Key has wrong length")
                file.close()
    except FileNotFoundError:
        print("Enter name first")

def loadText():
    try:
        with open(loadText_entry.get(), "rb") as file:
            text = file.read()
            binary_str = ''.join(format(byte, '08b') for byte in text)
            texty_entry.delete(0, tk.END)
            texty_entry.insert(0, text)
            file.close()
            return binary_str
    except FileNotFoundError:
        print("File doesn't exist")

def saveText():
    try:
        with open(saveText_entry.get(), "wb") as file:
                text = texty_entry.get()
                binary = ''.join(format(ord(char), '08b') for char in text)
                file.write(int(binary, 2).to_bytes((len(binary) + 7) // 8, byteorder='big'))
                file.close()
    except FileNotFoundError:
        print("Enter name first")
def loadCiphertext():
    try:
        with open(loadCiphertext_entry.get(), "r") as file:
            text = file.read()
            ciphertext_entry.delete(0, tk.END)
            ciphertext_entry.insert(0, text)
            file.close()
    except FileNotFoundError:
        print("File doesn't exist")

def saveCiphertext():
    try:
        with open(saveCiphertext_entry.get(), "w") as file:
            text = ciphertext_entry.get()
            file.write(text)
            file.close()
    except FileNotFoundError:
        print("Enter name first")

def char_to_bits(char):
    binary_string = bin(ord(char))[2:].zfill(8)
    bits = [int(bit) for bit in binary_string]
    return bits

def bits_to_char(bits):
    binary_string = ''.join(str(bit) for bit in bits)
    char_code = int(binary_string, 2)
    return chr(char_code)


def arrayToString(array):
    result = ""
    for i in array:
        if i == 1:
            result += "1"
        else:
            result +="0"
    return result

def stringToArray(stringToConvert):
    tmp = []
    for i in stringToConvert:
        if i == "1":
            tmp.append(1)
        else:
            tmp.append(0)
    return tmp

def create64BitsBlock(plaintext):
    result = ""
    for char in plaintext:
        charAsBits = char_to_bits(char)
        result += (arrayToString(charAsBits))
    if len(result) < 64:
        result += ((64 - len(result)) * "0")
    return result

def initialPermutation(textToPermute):
    result = ""
    for i in dt.IP:
        result +=textToPermute[i - 1]
    return result

def divide64BitsIntoLeftRihtHalf(bits):
    left = bits[:32]
    right = bits[32:]
    return left, right

def extendRightHalfOfData(rightHalf):
    result = ""
    for i in dt.E:
        result += rightHalf[i-1]
    return result

def create56BitsKey(key64Bits):
    key56Bits = ""
    for i in dt.PC1:
        key56Bits += key64Bits[i - 1]
    return key56Bits

def create48BitsKey(key56Bits):
    key48Bits = ""
    for i in dt.PC2:
        key48Bits += key56Bits[i - 1]
    return key56Bits

def moveKeyBitsIntoLeft(key, numberOfPositions):
    return key[numberOfPositions:] + key[:numberOfPositions]

def xorOnRightHalfAnd48BitsKey(rightHalf, key48Bits):
    result = ""
    for i in range(48):
        a = int(rightHalf[i])
        b = int(key48Bits[i])
        if (a + b) % 2 == 0:
            result += "0"
        else:
            result +="1"
    return result

def divideXorResultInto8x6BitBlocks(xorResult):
    result = []
    for i in range(8):
        tmp = ""
        for j in range(6):
            tmp += xorResult[(i * 6) + j]
        result.append(tmp)
    return result

def permutateWithSBoxes(dataToPermutate):
    result = ""
    tmp = 0
    for i in dataToPermutate:
        result += dt.Sboxes[tmp][i]
        tmp += 1
    return result

def permutateWithPBlock(dataToPermutate):
    result = ""
    for i in dt.P:
        result += dataToPermutate[i-1]
    return result

def xorOnLeftHalfAndPermutationWithPBlockResult(leftHalf, pBlockResult):
    result = ""
    for i in range(32):
        tmp = int(leftHalf[i]) + int(pBlockResult[i])
        if tmp%2 == 0:
            result += "0"
        else:
            result += "1"
    return result

def finalPermutation(dataToPermutate):
    result = ""
    for i in dt.IPMinus1:
        result += dataToPermutate[i-1]
    return result

def encode_to_base64(binary_string):
    binary_bytes = int(binary_string, 2).to_bytes((len(binary_string) + 7) // 8, byteorder='big')
    base64_bytes = base64.b64encode(binary_bytes)
    base64_string = base64_bytes.decode('ascii')
    return base64_string

def decode_from_base64(base64_string):
    base64_bytes = base64_string.encode('ascii')
    binary_bytes = base64.b64decode(base64_bytes)
    binary_string = bin(int.from_bytes(binary_bytes, byteorder='big'))[2:]
    padding = (8 - len(binary_string) % 8) % 8
    binary_string = '0' * padding + binary_string
    return binary_string

def generateKeysArray(key56Bits):
    result = []
    for i in range(16):
        result.append(moveKeyBitsIntoLeft(key56Bits, i+1))
    return result


def encrypt():
    text = loadText()
    result = ""
    if text is not None and key_entry.get() is not None:
        key = key_entry.get()
        key = create64BitsBlock(key)
        key = create56BitsKey(key)
        keysArray = generateKeysArray(key)
        for i in range(0, len(text), 8):
            message = text[i:i+8]
            message = create64BitsBlock(message)
            message = initialPermutation(message)
            left, right = divide64BitsIntoLeftRihtHalf(message)
            for i in range(16):
                rightCpy = right
                key48 = create48BitsKey(keysArray[i])
                right = extendRightHalfOfData(right)
                xorResult = xorOnRightHalfAnd48BitsKey(right, key48)
                blocks8Bits = divideXorResultInto8x6BitBlocks(xorResult)
                afterSBoxesPermutation = permutateWithSBoxes(blocks8Bits)
                pBlockPermutatuion = permutateWithPBlock(afterSBoxesPermutation)
                right = xorOnLeftHalfAndPermutationWithPBlockResult(left, pBlockPermutatuion)
                left = rightCpy
            finalConcatenate = right+left
            result += finalPermutation(finalConcatenate)

        ciphertext_entry.delete(0, tk.END)
        ciphertext_entry.insert(0, encode_to_base64(result))
        return encode_to_base64(result)

def decrypt():
    word = ""
    textToDecrypt = decode_from_base64(ciphertext_entry.get())
    result = ""
    if textToDecrypt is not None and key_entry.get() is not None:
        key = create64BitsBlock(key_entry.get())
        key = create56BitsKey(key)
        keysArray = generateKeysArray(key)
        for i in range(0, len(textToDecrypt), 64):
            message = textToDecrypt[i:i+64]
            message = initialPermutation(message)
            left, right = divide64BitsIntoLeftRihtHalf(message)
            for i in reversed(range(16)):
                rightCpy = right
                key48 = create48BitsKey(keysArray[i])
                right = extendRightHalfOfData(right)
                xorResult = xorOnRightHalfAnd48BitsKey(right, key48)
                blocks8Bits = divideXorResultInto8x6BitBlocks(xorResult)
                afterSBoxesPermutation = permutateWithSBoxes(blocks8Bits)
                pBlockPermutatuion = permutateWithPBlock(afterSBoxesPermutation)
                right = xorOnLeftHalfAndPermutationWithPBlockResult(left, pBlockPermutatuion)
                left = rightCpy
            finalConcatenate = right+left
            result += finalPermutation(finalConcatenate)
        for i in range(0, len(result), 8):
            if(result[i:i+8] != "00000000"):
                word += bits_to_char(result[i:i+8])

        byte_array = bytearray([int(word[i:i + 8], 2) for i in range(0, len(word), 8)])
        content = byte_array.decode('iso-8859-1')
        texty_entry.delete(0, tk.END)
        texty_entry.insert(0, content)
        return word


root = tk.Tk()
root.geometry("900x600")

key_frame = tk.Frame(root, bd=2, relief=tk.RAISED)
key_frame.place(x=250, y=0)

inner_frame = tk.Frame(key_frame)
inner_frame.pack(expand=True, fill=tk.BOTH, padx=50, pady=50)

textk_label = tk.Label(inner_frame, text="Key")
textk_label.grid(row=0, column=1)

key_label = tk.Label(inner_frame, text="Your key:", font=("Aerial", 8))
key_label.grid(row=1, column=0)

key_entry = tk.Entry(inner_frame, width=15, font=("Arial", 8))
key_entry.grid(row=1, column=1)

key_entry.bind("<Key>", lambda e: "break")

generate_button = tk.Button(inner_frame, text="Generate key", font=("Arial", 8), command=generate_key)
generate_button.grid(row=1, column=2, padx=10)

loadKey_label = tk.Label(inner_frame, text="Load key from file:", font=("Aerial", 8))
loadKey_label.grid(row=2, column=0)

loadKey_entry = tk.Entry(inner_frame, width=15, font=("Aerial", 8))
loadKey_entry.grid(row=2, column=1)

loadKey_button = tk.Button(inner_frame, text="Load", font=("Arial", 8), command=loadKey)
loadKey_button.grid(row=2, column=2, padx=10)

saveKey_label = tk.Label(inner_frame, text="Save key to file:", font=("Aerial", 8))
saveKey_label.grid(row=3, column=0)

saveKey_entry = tk.Entry(inner_frame, width=15, font=("Aerial", 8))
saveKey_entry.grid(row=3, column=1)

saveKey_button = tk.Button(inner_frame, text="Save", font=("Arial", 8), command=saveKey)
saveKey_button.grid(row=3, column=2, padx=10)

sd_frame = tk.Frame(root, bd=2, relief=tk.RAISED)
sd_frame.place(x=100 , y=200)

inner2_frame = tk.Frame(sd_frame)
inner2_frame.pack(expand=True, fill=tk.BOTH, padx=50, pady=50)

textz_label = tk.Label(inner2_frame, text="Encryption / Decryption")
textz_label.grid(row=0, column=0)

loadText_label = tk.Label(inner2_frame, text="Load text from file:", font=("Aerial", 8))
loadText_label.grid(row=1, column=0)

loadText_entry = tk.Entry(inner2_frame, width=15, font=("Aerial", 8))
loadText_entry.grid(row=2, column=0)

loadText_button = tk.Button(inner2_frame, text="Load", font=("Arial", 8), command=loadText)
loadText_button.grid(row=3, column=0, pady=10)

loadCiphertext_label = tk.Label(inner2_frame, text="Load ciphertext from file:", font=("Aerial", 8))
loadCiphertext_label.grid(row=1, column=1)

loadCiphertext_entry = tk.Entry(inner2_frame, width=15, font=("Aerial", 8))
loadCiphertext_entry.grid(row=2, column=1)

loadCiphertext_button = tk.Button(inner2_frame, text="Load", font=("Arial", 8), command=loadCiphertext)
loadCiphertext_button.grid(row=3, column=1, pady=10)

saveText_label = tk.Label(inner2_frame, text="Save text to file:", font=("Aerial", 8))
saveText_label.grid(row=1, column=2)

saveText_entry = tk.Entry(inner2_frame, width=15, font=("Aerial", 8))
saveText_entry.grid(row=2, column=2)

saveText_button = tk.Button(inner2_frame, text="Save", font=("Arial", 8), command=saveText)
saveText_button.grid(row=3, column=2, pady=10)

saveCiphertext_label = tk.Label(inner2_frame, text="Save ciphertext to file:", font=("Aerial", 8))
saveCiphertext_label.grid(row=1, column=3)

saveCiphertext_entry = tk.Entry(inner2_frame, width=15, font=("Aerial", 8))
saveCiphertext_entry.grid(row=2, column=3)

saveCiphertext_button = tk.Button(inner2_frame, text="Save", font=("Arial", 8), command=saveCiphertext)
saveCiphertext_button.grid(row=3, column=3, pady=10)

texty_label = tk.Label(inner2_frame, text="Text to encryption:", font=("Aerial", 8))
texty_label.grid(row=4, column=0)

texty_entry = tk.Entry(inner2_frame, width=30, font=("Aerial", 8))
texty_entry.grid(row=5, column=0)

texty_button = tk.Button(inner2_frame, text="Encrypt", font=("Arial", 8), command=encrypt)
texty_button.grid(row=5, column=1)

ciphertext_label = tk.Label(inner2_frame, text="Text to decryption:", font=("Aerial", 8))
ciphertext_label.grid(row=4, column=3)

ciphertext_entry = tk.Entry(inner2_frame, width=30, font=("Aerial", 8))
ciphertext_entry.grid(row=5, column=3)

ciphertext_button = tk.Button(inner2_frame, text="Decrypt", font=("Arial", 8), command=decrypt)
ciphertext_button.grid(row=5, column=2, padx=10)

root.mainloop()