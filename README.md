# DATA ENCRYPTION STANDARD (DES)
Python application that uses Data Encryption Standard for encrypting/decrypting files.
You can learn more about DES [HERE](https://en.wikipedia.org/wiki/Data_Encryption_Standard).
## ENCRYPTION
If you want to encode a message first thing is to enter 64 - bits key in the key section. You can do it by generating a random key or loading an existing one from the file:

<img src="https://user-images.githubusercontent.com/84719721/232807749-422009d3-00f4-43ef-bf0e-fcc0fdd13b3a.png" width="600" height="400" />

Here we're gonna generate a random key, remember to save the key to the file. (if you want to decode the message later).

![](https://user-images.githubusercontent.com/84719721/232807751-a57a1dd6-2779-47e5-8ff6-7ebba35bd8aa.png)

Now, it's time to provide some data to encrypt. You have to enter the file's name in the window above and click the "Load" button. After that, we can see a fragment of data in the bellow window:

![](https://user-images.githubusercontent.com/84719721/232807753-544eac8e-e4b9-4f71-bce8-34b9f744b781.png)

Everything is ready, it's time to encrypt. You have to click on Encrypt button which is on the right side of the "Text to encryption" window. The result will be shown in the "Text to decryption" window:

![](https://user-images.githubusercontent.com/84719721/232807755-7e922630-079a-4252-bd99-cf39d65b0973.png)

Now you can save encrypted data to a file. Enter the name of the file and click the "Save" button:

![](https://user-images.githubusercontent.com/84719721/232807756-d6e9901c-059d-475c-b7ec-19d6d60a8bc1.png)

After running the encrypted file in Notepad we can see the encryption result:

<img src="https://user-images.githubusercontent.com/84719721/232807739-a3081d3e-cfca-4f65-b31f-5a69c6aa4b37.png" width="553" height="475" />

## DECRYPTION
The decryption process is very similar to encryption. First, you have to enter the proper key - otherwise, the file won't be decoded right. After that, you can load data from the file by entering the file's name and confirming it with the "Load" button. You can see loaded data in the "Text to decryption" window:

![](https://user-images.githubusercontent.com/84719721/232807760-8dd9bdfd-4307-41a6-b555-3d03f2845803.png)

Now, it's time to decrypt ("Decrypt" button) and save it to the file ("Save text to file" window):

![](https://user-images.githubusercontent.com/84719721/232807762-6f7897eb-0172-42a7-b2a7-681cc262560d.png)

If provided key was right, you can see result of the decryption:

![](https://user-images.githubusercontent.com/84719721/232807745-97be77ae-897e-4d97-aa82-77f288a3ed6f.png)


## CHECKING BY CONTROL SUM
We can make sure, that file before and after encoding/decoding is still the same. We'll do that by generating checksum for both files. If the checksums are the same, files were not corrupted or modified during encryption/decryption.

```
PS C:\Cryptography> Get-FileHash test.jpg

Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
SHA256          A5DE146C4965F9D8780B5238AB14FDFED0DAEDD4E0B7E5D7EE1B09BB7D02126E       C:\...


PS C:\Cryptography> Get-FileHash decrypted_file.jpg

Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
SHA256          A5DE146C4965F9D8780B5238AB14FDFED0DAEDD4E0B7E5D7EE1B09BB7D02126E       C:\...

```
