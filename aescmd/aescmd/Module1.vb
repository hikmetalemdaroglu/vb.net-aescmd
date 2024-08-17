' Imports System
Imports System.IO
Imports System.Collections.Generic
Imports System.Text
Imports Org.BouncyCastle.Crypto
Imports Org.BouncyCastle.Crypto.Encodings
Imports Org.BouncyCastle.Crypto.Engines
Imports Org.BouncyCastle.OpenSsl
Imports Org.BouncyCastle.Crypto.Parameters
Imports System.Security.Cryptography
Imports System.Threading
Imports System.Reflection

Module Module1
    ' aescmd "C:\i24\supp\key"  "abcd" "en = encrypt / den = decrypt" 
    Dim pubFile As String = Nothing
    Dim prvFile As String = Nothing
    Dim outputFile As String = Nothing
    Dim filePath As String = Nothing
    Dim plainText As String = Nothing
    Dim OprStatu As String = Nothing
    Dim cihperText As String = Nothing
    Dim decryptedCipherText As String = Nothing
    Dim vSleep As Int32 = 3000
    Declare Sub Sleep Lib "kernel32.dll" (ByVal Milliseconds As Integer)

    Public Sub Main(ByVal args As String())
        Dim argument As String = Nothing
        Dim argArr As String() = Nothing

        If args.Count <> 4 Then
            'Console.Write("ERROR : Parameters is missing ! " &  & args.Count)
            'Environment.[Exit](0)
            EnvExit("ERROR : Parameters Is Missing! " & args.Count, vSleep)
        End If

        argument = String.Join(";", args)
        argArr = argument.Split(";"c)

        ' Console.Write(argument.Count & "  ")
        ' Console.ReadKey()

        For i As Integer = 0 To argArr.Length - 1
            If i = 0 Then filePath = argArr(i)
            If i = 1 Then plainText = argArr(i)
            If i = 2 Then OprStatu = argArr(i)
            If i = 3 Then outputFile = argArr(i)
            'Console.WriteLine(argArr(i))

            ' plainText = "ZGBcIvmPhmAzl7JtvXmMVmgbpvJB2S9/vmKF2xSuRsnEAIVVkzaY+LTEaUEEBnQI6X7pZXNjot1+O0SU6oDI/ZZWZC4dx3OP9bO3OTTipZmXt+Q6k/s/X8f77aBJV1djWDJ+jN+leEs3Qou8JmFlJyUbvMRxGnU4vOgBQNlpicTouBNYb0oFdRogO6FOqr2CnvMCpPIICz46uYFi1zoKsXgbd+WWrkeMJnglR5dhc+zzsH6wSqcTFLjDBIessmibew+dc1dUM1NXfCa+4THcOTobjrOw5hCU2bvxsMFZjoD75DY9IDPRaW1i6wp3NoZPKOzIFToCmFuDnEEo2Vg6Ow=="
            ' OprStatu = "den"
            ' outputFile = "c:\temp\output.den"
        Next
        If filePath = "" Then
            'Console.WriteLine("filePath is empty : " & filePath)
            'Environment.[Exit](0)
            EnvExit("filePath is empty : " & filePath, vSleep)
        End If
        If plainText = "" Then
            'Console.WriteLine("plainText is empty : " & plainText)
            'Environment.[Exit](0)
            EnvExit("plainText is empty : " & plainText, vSleep)
        End If
        If OprStatu = "" Then
            EnvExit("Operation Type is empty : " & OprStatu, vSleep)
            'Environment.[Exit](0)
        End If
        If outputFile = "" Then
            EnvExit("Output File is empty : " & OprStatu, vSleep)
            Environment.[Exit](0)
        End If

        pubFile = filePath + "\" + "pub.pem"
        prvFile = filePath + "\" + "prv.pem"

        If OprStatu = "en" Then
            If System.IO.File.Exists(pubFile) Then
                cihperText = Encrypt(plainText)
                'Console.WriteLine(cihperText)
                FoutputResult(cihperText)
            Else
                EnvExit("Pem file doesn't exist", vSleep)
                Environment.[Exit](0)
            End If
        End If
        If OprStatu = "den" Then
            If System.IO.File.Exists(prvFile) Then
                cihperText = plainText
                decryptedCipherText = Decrypt(cihperText)
                'Console.WriteLine(decryptedCipherText)
                FoutputResult(decryptedCipherText)
            Else
                'Console.WriteLine("Prv file doesn't exist")
                'Environment.[Exit](0)
                EnvExit("Prv file doesn't exist", vSleep)
            End If
        End If
        Environment.[Exit](0)
    End Sub
    Sub FoutputResult(ByVal result As String)
        Try
            File.WriteAllText(outputFile, result)
            Console.WriteLine($"Result written to {outputFile}")
        Catch ex As Exception
            'Console.WriteLine($"Error writing to file: {ex.Message}")
            EnvExit($"Error writing to file: {ex.Message}", vSleep)
        End Try
    End Sub
    Sub EnvExit(ByVal pMessage As String, ByVal intWait As Int32)
        If pMessage <> "" Then
            Console.WriteLine(pMessage)
            If intWait <> 0 Then Thread.Sleep(intWait)
        End If
        Environment.[Exit](0)
    End Sub

    Public Function Encrypt(ByVal plainText As String) As String
        Dim plainTextBytes As Byte() = Encoding.UTF8.GetBytes(plainText)
        ' Dim pr As PemReader = New PemReader(CType(File.OpenText("./pub.pem"), StreamReader))
        Dim Pr As PemReader = New PemReader(CType(File.OpenText(pubFile), StreamReader))
        Dim keys As RsaKeyParameters = CType(Pr.ReadObject(), RsaKeyParameters)
        Dim eng As OaepEncoding = New OaepEncoding(New RsaEngine())
        eng.Init(True, keys)
        Dim length As Integer = plainTextBytes.Length
        Dim blockSize As Integer = eng.GetInputBlockSize()
        Dim cipherTextBytes As List(Of Byte) = New List(Of Byte)()
        Dim chunkPosition As Integer = 0

        While chunkPosition < length
            Dim chunkSize As Integer = Math.Min(blockSize, length - chunkPosition)
            cipherTextBytes.AddRange(eng.ProcessBlock(plainTextBytes, chunkPosition, chunkSize))
            chunkPosition += blockSize
        End While

        Return Convert.ToBase64String(cipherTextBytes.ToArray())
    End Function
    Public Function Create_HMACSHA256_Sign(ByVal SecretKey As String, ByVal Message As String) As String
        Dim Encoding = New Text.ASCIIEncoding()
        Dim KeyByte As Byte() = Encoding.GetBytes(SecretKey)
        Dim MessageBytes As Byte() = Encoding.GetBytes(Message)
        Using Hmacsha256 = New HMACSHA256(KeyByte)
            Dim HashBytes As Byte() = Hmacsha256.ComputeHash(MessageBytes)
            Return BitConverter.ToString(HashBytes).Replace("-", "").ToLower()
        End Using
    End Function
    Public Function CreateHash(ByVal rawData As String, ByVal secretKey As String) As String
        Dim alg As HashAlgorithm = New HMACSHA256(Text.Encoding.UTF8.GetBytes(secretKey))
        Dim bytes As Byte() = alg.ComputeHash(Text.Encoding.UTF8.GetBytes(rawData))
        Dim x As String = BitConverter.ToString(bytes).Replace("-", "").ToLower()
        Return Convert.ToBase64String(Text.Encoding.UTF8.GetBytes(x))
    End Function
    Public Function Decrypt(ByVal cipherText As String) As String
        Dim cipherTextBytes As Byte() = Convert.FromBase64String(cipherText)
        ' Dim pr As PemReader = New PemReader(CType(File.OpenText("./prv.pem"), StreamReader))
        Dim pr As PemReader = New PemReader(CType(File.OpenText(prvFile), StreamReader))
        Dim keys As AsymmetricCipherKeyPair = CType(pr.ReadObject(), AsymmetricCipherKeyPair)
        Dim eng As OaepEncoding = New OaepEncoding(New RsaEngine())
        eng.Init(False, keys.[Private])
        Dim length As Integer = cipherTextBytes.Length
        Dim blockSize As Integer = eng.GetInputBlockSize()
        Dim plainTextBytes As List(Of Byte) = New List(Of Byte)()
        Dim chunkPosition As Integer = 0

        While chunkPosition < length
            Dim chunkSize As Integer = Math.Min(blockSize, length - chunkPosition)
            plainTextBytes.AddRange(eng.ProcessBlock(cipherTextBytes, chunkPosition, chunkSize))
            chunkPosition += blockSize
        End While
        Return Encoding.UTF8.GetString(plainTextBytes.ToArray())
    End Function
End Module
