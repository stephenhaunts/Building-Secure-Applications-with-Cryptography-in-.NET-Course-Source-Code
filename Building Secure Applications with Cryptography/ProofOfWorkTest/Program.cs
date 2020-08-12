namespace BlockChainCourse.ProofOfWorkTest
{
    class Program
    {
        static void Main(string[] args)
        {
            ProofOfWork pow0 = new ProofOfWork("Mary had a little lamb", 0);
            ProofOfWork pow1 = new ProofOfWork("Mary had a little lamb", 1);
            ProofOfWork pow2 = new ProofOfWork("Mary had a little lamb", 2);
            ProofOfWork pow3 = new ProofOfWork("Mary had a little lamb", 3);
            ProofOfWork pow4 = new ProofOfWork("Mary had a little lamb", 4);
            ProofOfWork pow5 = new ProofOfWork("Mary had a little lamb", 5);
            ProofOfWork pow6 = new ProofOfWork("Mary had a little lamb", 6);

            pow0.CalculateProofOfWork();
            pow1.CalculateProofOfWork();
            pow2.CalculateProofOfWork();
            pow3.CalculateProofOfWork();
            pow4.CalculateProofOfWork();
            pow5.CalculateProofOfWork();
            pow6.CalculateProofOfWork();
        }
    }
}
