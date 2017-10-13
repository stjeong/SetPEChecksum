using System;
using System.IO;
using Workshell.PE;

namespace SetPEChecksum
{
    class Program
    {
        // https://github.com/mrexodia/portable-executable-library/blob/master/pe_lib/pe_checksum.cpp#L43
        static int Main(string[] args)
        {
            if (args.Length != 1 && args.Length != 2)
            {
                Console.WriteLine("[options] file_path");
                Console.WriteLine("/s - calc & set checksum");
                return 1;
            }

            bool setNewChecksum = false;
            string filePath = null;

            if (args[0] == "/s" || args[0] == "-s")
            {
                setNewChecksum = true;
                filePath = args[1];
            }
            else
            {
                filePath = args[0];
            }

            uint currentCheckSum = 0;
            uint newCheckSum = 0;
            uint checkSumPos = 0;

            using (Workshell.PE.ExecutableImage pe = Workshell.PE.ExecutableImage.FromFile(filePath))
            {
                currentCheckSum = pe.NTHeaders.OptionalHeader.CheckSum;
                Console.WriteLine($"Current Checksum: {currentCheckSum}(0x{currentCheckSum.ToString("x")})");

                newCheckSum = CalcChecksum(pe, out checkSumPos);
                Console.WriteLine($"New Checksum: {newCheckSum}(0x{newCheckSum.ToString("x")})");
            }

            if (setNewChecksum == true && (currentCheckSum != newCheckSum))
            {
                byte[] contents = File.ReadAllBytes(filePath);
                byte[] newCheckSumBuffer = BitConverter.GetBytes(newCheckSum);
                Array.Copy(newCheckSumBuffer, 0, contents, checkSumPos, 4);

                try
                {
                    File.WriteAllBytes(filePath, contents);
                }
                catch (System.IO.IOException)
                {
                    string newFilePath = filePath + ".new";
                    Console.WriteLine($"New file({newFilePath}) created because it is being used by another process.");
                    File.WriteAllBytes(newFilePath, contents);
                }
            }

            return 0;
        }

        private static uint CalcChecksum(ExecutableImage pe, out uint checkSumPos)
        {
            const uint checksum_pos_in_optional_headers = 64;

            checkSumPos = (uint)pe.NTHeaders.OptionalHeader.Location.FileOffset + checksum_pos_in_optional_headers;

            uint fileSize = (uint)pe.GetBytes().Length;

            MemoryStream ms = new MemoryStream(pe.GetBytes());

            byte[] bytes4 = new byte[4];
            int pos = 0;

            ulong calcSum = 0;
            ulong top = (ulong)0xFFFFFFFF + 1;

            while (ms.Read(bytes4, pos, 4) == 4)
            {
                uint dw = BitConverter.ToUInt32(bytes4, 0);

                if (ms.Position == checkSumPos + 4)
                {
                    continue;
                }

                calcSum = (calcSum & 0xFFFFFFFF) + dw + (calcSum >> 32);
                if (calcSum > top)
                {
                    calcSum = (calcSum & 0xFFFFFFFF) + (calcSum >> 32);
                }
            }

            calcSum = (calcSum & 0xffff) + (calcSum >> 16);
            calcSum = (calcSum) + (calcSum >> 16);
            calcSum = calcSum & 0xffff;

            calcSum += (uint)fileSize;

            return (uint)calcSum;
        }
    }
}
