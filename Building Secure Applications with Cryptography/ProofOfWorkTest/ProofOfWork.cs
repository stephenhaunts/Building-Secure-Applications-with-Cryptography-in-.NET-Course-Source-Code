using System;
using System.Diagnostics;
using System.Text;
using BlockChainCourse.Cryptography;

namespace BlockChainCourse.ProofOfWorkTest
{
    public class ProofOfWork
    {
        public string MyData { get; private set; }
        public int Difficulty { get; private set; }
        public int Nonce { get; private set; }

        public ProofOfWork(string dataToHash, int difficulty)
        {
            MyData = dataToHash;
            Difficulty = difficulty;
        }

        public string CalculateProofOfWork()
        {
            string difficulty = DifficultyString();
            Stopwatch stopWatch = new Stopwatch();
            stopWatch.Start();

            while(true)
            {
                string hashedData = Convert.ToBase64String(HashData.ComputeHashSha256(Encoding.UTF8.GetBytes(Nonce + MyData)));

                if (hashedData.StartsWith(difficulty, StringComparison.Ordinal))
                {
                    stopWatch.Stop();
                    TimeSpan ts = stopWatch.Elapsed;

                    // Format and display the TimeSpan value.
                    string elapsedTime = String.Format("{0:00}:{1:00}:{2:00}.{3:00}", ts.Hours, ts.Minutes, ts.Seconds, ts.Milliseconds / 10);
                    
                    Console.WriteLine("Difficulty Level " + Difficulty + " - Nonce = " + Nonce + " - Elapsed = " + elapsedTime +  " - " + hashedData);
                    return hashedData;
                }

                Nonce++;
            }
        }

        private string DifficultyString()
        {
            string difficultyString = string.Empty;

            for (int i = 0; i < Difficulty; i++ )
            {
                difficultyString += "0";    
            }

            return difficultyString;
        }
    }
}
