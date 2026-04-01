using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class AESEncryptFile
{
    // --- 1. AES CORE TABLES ---
    private static readonly byte[] SBox = {
        //00   01   02     03   04     05    06    07    08    09    0A    0B    0C    0D    0E    0F
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 
    };

    private static readonly byte[] InvSBox = {
        //00   01   02     03   04     05    06    07    08    09    0A    0B    0C    0D    0E    0F
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    };

    private static readonly byte[] Rcon = {
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a
    }; //phép nhân 2 (dịch trái 1 bit) trong GF(2^8) nếu byte > 0x80 thì XOR với 0x1b -->bảng Rcon

    // --- PRECOMPUTED GF(2^8) MULTIPLICATION TABLES ---
    // Tra bảng O(1) thay vì gọi GFMul() với vòng lặp 8 lần mỗi lần gọi
    // Dùng cho MixColumns (Mul2, Mul3) và InvMixColumns (Mul9, Mul11, Mul13, Mul14)
    private static readonly byte[] Mul2 = GenerateMultiplyTable(0x02);
    private static readonly byte[] Mul3 = GenerateMultiplyTable(0x03);
    private static readonly byte[] Mul9 = GenerateMultiplyTable(0x09);
    private static readonly byte[] Mul11 = GenerateMultiplyTable(0x0b);
    private static readonly byte[] Mul13 = GenerateMultiplyTable(0x0d);
    private static readonly byte[] Mul14 = GenerateMultiplyTable(0x0e);

    private static byte[] GenerateMultiplyTable(byte multiplier)
    {
        byte[] table = new byte[256];
        for (int i = 0; i < 256; i++)
        {
            table[i] = GFMul(multiplier, (byte)i);
        }
        return table;
    }

    // --- 2. GF(2^8) MATH ---
    private static byte GFMul(byte a, byte b)
    {
        byte p = 0;
        for (int counter = 0; counter < 8; counter++)
        {
            if ((b & 1) != 0)
                p ^= a;
            bool hi_bit_set = (a & 0x80) != 0;
            a <<= 1;
            if (hi_bit_set)
                a ^= 0x1b; // polynomial x^8 + x^4 + x^3 + x + 1
            b >>= 1;
        }
        return p;
    }
    /*
        Dịch phải bit của b để đọc hệ số (nếu = 1 thì p ^= a) đồng thời dịch bit của a
        để tăng số mũ tương ứng với hệ số tiếp theo của b được đọc,
        kiểm tra bit cao nhất của a nếu = 1 (tràn) thì a ^= 0x1b
    */

    // --- 3. KEY EXPANSION ---
    private static void RotWord(byte[] word)
    {
        byte temp = word[0];
        word[0] = word[1];
        word[1] = word[2];
        word[2] = word[3];
        word[3] = temp;
    }

    private static void SubWord(byte[] word)
    {
        word[0] = SBox[word[0]];
        word[1] = SBox[word[1]];
        word[2] = SBox[word[2]];
        word[3] = SBox[word[3]];
    }

    private static byte[] KeyExpansion(byte[] key)
    {
        int nk = key.Length / 4; //số từ khóa: ví dụ aes-128 = 32bytes/4 = 8 từ khóa
        int nr = nk + 6; //số vòng AES
        byte[] roundKeys = new byte[4 * 4 * (nr + 1)]; // 4 bytes/word * 4 words/round * (nr+1) rounds mỗi round làm việc với block 128bit

        // Copy khóa ban đầu vào đầu mảng roundKeys (nk words = key.Length bytes)
        Array.Copy(key, roundKeys, key.Length);

        byte[] temp = new byte[4];

        for (int i = nk; i < 4 * (nr + 1); i++) //4*(nr+1) là tổng số lượng word cần
        {
            Array.Copy(roundKeys, (i - 1) * 4, temp, 0, 4); //copy 4 bytes từ roundKeys[(i - 1) * 4] (bắt đầu từ bytes đầu tiên của word ngay trước i) vào temp, mỗi lần chạy for lại cập nhật temp mới

            if (i % nk == 0)
            {
                RotWord(temp);
                SubWord(temp);
                temp[0] ^= Rcon[i / nk];
            }
            else if (nk > 6 && i % nk == 4)
            {
                SubWord(temp);
            }
            //XOR các bytes
            roundKeys[i * 4 + 0] = (byte)(roundKeys[(i - nk) * 4 + 0] ^ temp[0]);
            roundKeys[i * 4 + 1] = (byte)(roundKeys[(i - nk) * 4 + 1] ^ temp[1]);
            roundKeys[i * 4 + 2] = (byte)(roundKeys[(i - nk) * 4 + 2] ^ temp[2]);
            roundKeys[i * 4 + 3] = (byte)(roundKeys[(i - nk) * 4 + 3] ^ temp[3]);
        }

        return roundKeys;
    }

    // --- 4. STATE OPERATIONS (ENCRYPT) ---
    private static void AddRoundKey(byte[] state, byte[] roundKeys, int round) //Xử lý theo cột (XOR với state theo cột)
    {
        for (int c = 0; c < 4; c++)
        {
            for (int r = 0; r < 4; r++)
            {
                state[r + c * 4] ^= roundKeys[round * 16 + c * 4 + r];
                //Mỗi culumn cách nhau 4 bytes (*4) & Mỗi round cách nhau 16 bytes (*16)
            }
        }
    }

    private static void SubBytes(byte[] state)
    {
        for (int i = 0; i < 16; i++)
        {
            state[i] = SBox[state[i]];
        }
    }

    private static void ShiftRows(byte[] state)
    {
        byte[] temp = new byte[16];
        Array.Copy(state, temp, 16);
        // Culumn-major
        // Row 0: No shift
        // Row 1: Shift left 1
        state[1] = temp[5]; state[5] = temp[9]; state[9] = temp[13]; state[13] = temp[1];
        // Row 2: Shift left 2
        state[2] = temp[10]; state[6] = temp[14]; state[10] = temp[2]; state[14] = temp[6];
        // Row 3: Shift left 3
        state[3] = temp[15]; state[7] = temp[3]; state[11] = temp[7]; state[15] = temp[11];
    }

    private static void MixColumns(byte[] state)
    {
        byte[] temp = new byte[16];
        Array.Copy(state, temp, 16);

        for (int c = 0; c < 4; c++)
        {
            int idx = c * 4;
            byte s0 = state[idx + 0], s1 = state[idx + 1], s2 = state[idx + 2], s3 = state[idx + 3];
            temp[idx + 0]     = (byte)(Mul2[s0] ^ Mul3[s1] ^ s2 ^ s3);
            temp[idx + 1] = (byte)(s0 ^ Mul2[s1] ^ Mul3[s2] ^ s3);
            temp[idx + 2] = (byte)(s0 ^ s1 ^ Mul2[s2] ^ Mul3[s3]);
            temp[idx + 3] = (byte)(Mul3[s0] ^ s1 ^ s2 ^ Mul2[s3]);
        }

        Array.Copy(temp, state, 16);
        /*Ma trận MixColumns
            |02 03 01 01|
            |01 02 03 01|
            |01 01 02 03|
            |03 01 01 02|
        */
    }


    // --- 5. STATE OPERATIONS (DECRYPT) ---
    private static void InvSubBytes(byte[] state)
    {
        for (int i = 0; i < 16; i++)
        {
            state[i] = InvSBox[state[i]];
        }
    }

    private static void InvShiftRows(byte[] state)
    {
        byte[] temp = new byte[16];
        Array.Copy(state, temp, 16);

        // Row 0: No shift
        // Row 1: Shift right 1
        state[1] = temp[13]; state[5] = temp[1]; state[9] = temp[5]; state[13] = temp[9];
        // Row 2: Shift right 2
        state[2] = temp[10]; state[6] = temp[14]; state[10] = temp[2]; state[14] = temp[6];
        // Row 3: Shift right 3
        state[3] = temp[7]; state[7] = temp[11]; state[11] = temp[15]; state[15] = temp[3];
    }

    private static void InvMixColumns(byte[] state)
    {
        byte[] temp = new byte[16];
        Array.Copy(state, temp, 16);

        for (int c = 0; c < 4; c++)
        {
            int idx = c * 4;
            byte s0 = state[idx + 0], s1 = state[idx + 1], s2 = state[idx + 2], s3 = state[idx + 3];
            temp[idx + 0]     = (byte)(Mul14[s0] ^ Mul11[s1] ^ Mul13[s2] ^ Mul9[s3]);
            temp[idx + 1] = (byte)(Mul9[s0]  ^ Mul14[s1] ^ Mul11[s2] ^ Mul13[s3]);
            temp[idx + 2] = (byte)(Mul13[s0] ^ Mul9[s1]  ^ Mul14[s2] ^ Mul11[s3]);
            temp[idx + 3] = (byte)(Mul11[s0] ^ Mul13[s1] ^ Mul9[s2]  ^ Mul14[s3]);
        }

        Array.Copy(temp, state, 16);
        /*Ma trận Inverse MixColumns
            | 0e 0b 0d 09 |
            | 09 0e 0b 0d |
            | 0d 09 0e 0b |
            | 0b 0d 09 0e |
        */
    }

    // --- 6. BLOCK LEVEL ENCRYPT / DECRYPT ---
    private static byte[] EncryptBlock(byte[] input, byte[] roundKeys, int nr)
    {
        byte[] state = new byte[16];
        Array.Copy(input, state, 16);

        AddRoundKey(state, roundKeys, 0);

        for (int round = 1; round < nr; round++)
        {
            SubBytes(state);
            ShiftRows(state);
            MixColumns(state);
            AddRoundKey(state, roundKeys, round);
        }

        SubBytes(state);
        ShiftRows(state);
        AddRoundKey(state, roundKeys, nr);

        return state;
    }

    private static byte[] DecryptBlock(byte[] input, byte[] roundKeys, int nr)
    {
        byte[] state = new byte[16];
        Array.Copy(input, state, 16);

        AddRoundKey(state, roundKeys, nr);

        for (int round = nr - 1; round > 0; round--)
        {
            InvShiftRows(state);
            InvSubBytes(state);
            AddRoundKey(state, roundKeys, round);
            InvMixColumns(state);
        }

        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, roundKeys, 0);

        return state;
    }

    // --- 7. PKCS7 PADDING ---
    private static byte[] ApplyPKCS7Padding(byte[] input)
    {
        int paddingLen = 16 - (input.Length % 16);
        byte[] padded = new byte[input.Length + paddingLen];
        Array.Copy(input, padded, input.Length);
        for (int i = input.Length; i < padded.Length; i++)
        {
            padded[i] = (byte)paddingLen; //gán tất cả bytes thiếu = số lượng byte cần thêm
        }
        return padded;
    }

    private static byte[] RemovePKCS7Padding(byte[] input)
    {
        if (input.Length == 0) return input;
        int paddingLen = input[^1];
        if (paddingLen < 1 || paddingLen > 16) //kiểm tra byte cuối
        {
            throw new Exception("Lỗi: Padding không hợp lệ (sai khóa hoặc dữ liệu bị hỏng).");
        }

        // Kiểm tra đúng chuẩn PKCS7: Toàn bộ [paddingLen] byte cuối phải có giá trị bằng paddingLen
        for (int i = 0; i < paddingLen; i++)
        {
            if (input[input.Length - paddingLen + i] != paddingLen)
            {
                throw new Exception("Lỗi: Padding không hợp lệ (sai khóa hoặc dữ liệu bị hỏng).");
            }
        }

        byte[] unpadded = new byte[input.Length - paddingLen];
        Array.Copy(input, unpadded, unpadded.Length);
        return unpadded;
    }

    // --- 8. CBC MODE ENCRYPTION / DECRYPTION ---
    private static void XorBlock(byte[] block, byte[] xorBytes)
    {
        for (int i = 0; i < 16; i++)
        {
            block[i] ^= xorBytes[i];
        }
    }

    public static byte[] EncryptCBC(byte[] data, byte[] key)
    {
        byte[] roundKeys = KeyExpansion(key);
        int nr = roundKeys.Length / 16 - 1; //  byte[] roundKeys = new byte[4 * 4 * (nr + 1)];

        byte[] paddedData = ApplyPKCS7Padding(data);
        byte[] encryptedData = new byte[16 + paddedData.Length]; // 16 bytes IV + Encrypted Data

        // Sinh IV (Initialization vector) ngẫu nhiên an toàn 16 bytes
        byte[] iv = RandomNumberGenerator.GetBytes(16); //Cryptographically Secure Random Number Generator (CSPRNG)
        Array.Copy(iv, 0, encryptedData, 0, 16);

        byte[] previousBlock = new byte[16];
        Array.Copy(iv, previousBlock, 16);

        for (int i = 0; i < paddedData.Length; i += 16)
        {
            byte[] block = new byte[16];
            Array.Copy(paddedData, i, block, 0, 16);

            // CBC XOR
            XorBlock(block, previousBlock);
            
            byte[] encryptedBlock = EncryptBlock(block, roundKeys, nr);
            Array.Copy(encryptedBlock, 0, encryptedData, 16 + i, 16);
            Array.Copy(encryptedBlock, previousBlock, 16); // cập nhật previousBlock
        }

        return encryptedData;
    }

    public static byte[] DecryptCBC(byte[] encryptedData, byte[] key)
    {
        if (encryptedData.Length < 16 || encryptedData.Length % 16 != 0)
            throw new Exception("Lỗi: Dữ liệu mã hóa không hợp lệ (chiều dài sai).");

        byte[] roundKeys = KeyExpansion(key);
        int nr = roundKeys.Length / 16 - 1;

        // Trích xuất IV
        byte[] iv = new byte[16];
        Array.Copy(encryptedData, 0, iv, 0, 16);

        byte[] decryptedDataPadded = new byte[encryptedData.Length - 16];
        byte[] previousBlock = new byte[16];
        Array.Copy(iv, previousBlock, 16);

        for (int i = 16; i < encryptedData.Length; i += 16)
        {
            byte[] block = new byte[16];
            Array.Copy(encryptedData, i, block, 0, 16);

            byte[] decryptedBlock = DecryptBlock(block, roundKeys, nr);
            
            // CBC XOR
            XorBlock(decryptedBlock, previousBlock);

            Array.Copy(decryptedBlock, 0, decryptedDataPadded, i - 16, 16);
            Array.Copy(block, previousBlock, 16); // Cập nhật previousBlock
        }
        return RemovePKCS7Padding(decryptedDataPadded);
    }

    // --- 9. CONSOLE MENU & FILE I/O ---
    public static void Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        string currentDir = Directory.GetCurrentDirectory();
        string inputFilePath = Path.Combine(currentDir, "input.txt");
        string encryptedFilePath = Path.Combine(currentDir, "encrypted.bin");
        string decryptedFilePath = Path.Combine(currentDir, "decrypted.txt");

        // Tự tạo file input nếu chưa có
        if (!File.Exists(inputFilePath))
        {
            File.WriteAllText(inputFilePath, "New input file test😊😊😒😁😁😁");
            Console.WriteLine($"[Info] Đã tạo file test: {inputFilePath}");
        }

        while (true)
        {
            Console.WriteLine("\n===== AES File Encryption System (CBC Mode) =====");
            Console.WriteLine($"Thư mục làm việc: {currentDir}");
            Console.WriteLine("1. Mã hóa file (input.txt)");
            Console.WriteLine("2. Giải mã file (encrypted.bin)");
            Console.WriteLine("3. Thoát");
            Console.Write("Lựa chọn (1-3): ");
            string? choice = Console.ReadLine()?.Trim();

            if (choice == "3") break;

            if (choice == "1" || choice == "2")
            {
                Console.Write("Nhập khóa (128/192/256 bit): ");
                string? keyString = Console.ReadLine();
                if (string.IsNullOrEmpty(keyString))
                {
                    Console.WriteLine("Khóa trống!!!");
                    continue;
                }
                
                byte[] keyBytes = Encoding.UTF8.GetBytes(keyString);
                // Kiểm tra kích thước byte để đảm bảo khóa đủ (kí tự có dấu utf-8 dễ làm khóa bị dài hơn)
                if (keyBytes.Length != 16 && keyBytes.Length != 24 && keyBytes.Length != 32)
                {
                    Console.WriteLine($"[Lỗi] Khóa không hợp lệ: {keyBytes.Length} bytes (UTF-8)");
                    continue;
                }

                Stopwatch sw = new();
                try
                {
                    if (choice == "1")
                    {
                        if (!File.Exists(inputFilePath))
                        {
                            Console.WriteLine($"[Lỗi] Không tìm thấy file: {inputFilePath}");
                            continue;
                        }

                        Console.WriteLine("Đang bắt đầu mã hóa...");
                        byte[] fileData = File.ReadAllBytes(inputFilePath);
                        
                        sw.Start();
                        byte[] encryptedData = EncryptCBC(fileData, keyBytes);
                        sw.Stop();
                        
                        File.WriteAllBytes(encryptedFilePath, encryptedData);
                        Console.WriteLine($"[Thành công] Đã mã hóa xong. Dữ liệu lưu tại: {encryptedFilePath}");
                        Console.WriteLine($"Thời gian mã hóa: {sw.Elapsed.TotalSeconds:F5} s");
                    }
                    else if (choice == "2")
                    {
                        if (!File.Exists(encryptedFilePath))
                        {
                            Console.WriteLine($"[Lỗi] Không tìm thấy file đã mã hóa tại: {encryptedFilePath}");
                            continue;
                        }

                        Console.WriteLine("Đang bắt đầu giải mã...");
                        byte[] encryptedData = File.ReadAllBytes(encryptedFilePath);
                        
                        sw.Start();
                        byte[] decryptedData = DecryptCBC(encryptedData, keyBytes);
                        sw.Stop();
                        
                        File.WriteAllBytes(decryptedFilePath, decryptedData);
                        Console.WriteLine($"[Thành công] Đã giải mã xong. Dữ liệu lưu tại: {decryptedFilePath}");
                        Console.WriteLine($"Thời gian giải mã: {sw.Elapsed.TotalSeconds:F5} s");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[Lỗi]: {ex.Message}");
                }
            }
            else
            {
                Console.WriteLine("Lựa chọn không hợp lệ.");
            }
        }
    }
}
