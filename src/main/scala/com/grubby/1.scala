package com.grubby

import scala.io.Source


object CryptoPals {


  val enCharFrequency:Map[String,Double] = Map (
    "E" -> 0.127, "T" -> 0.091, "A" -> 0.082, "O" -> 0.075, "I" -> 0.07, "N" -> 0.067,
    "S" -> 0.063, "H" -> 0.061, "R" -> 0.060, "D" -> 0.043, "L" -> 0.04, "U" -> 0.028,
    "C" -> 0.028, "M" -> 0.024, "W" -> 0.024, "F" -> 0.022, "Y" -> 0.02, "G" -> 0.02,
    "P" -> 0.019, "B" -> 0.015, "V" -> 0.010, "K" -> 0.008, "X" -> 0.002, "J" -> 0.002,
    "Q" -> 0.001, "Z" -> 0.001, " " -> 0.18, "." -> 0.065, "," -> 0.065, "'" -> 0.024,
    "\"" -> 0.026, "-" -> 0.015
  )

  def main(args:Array[String]):Unit = {
    /*
    val res:Array[(Int,String,Double)] = (0 to 127).map { c =>
      val hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
      val string = xorStringSingleByte(hex, c.toChar)
      val stat = chiSquaredFit(string)
      (c,string,stat)
    }.toArray

    res.sortBy(_._3).take(1).foreach { r =>
      println("char: " + r._1 + " string: " + r._2 + " stat: " + r._3)
    }

    val lines = Source.fromFile("/Users/tom/Scala/m2/cyphers.txt").getLines.toList
    val scoreStrings:Array[(Double,String,Int)] = lines.flatMap { line =>
      val res:Array[(Int,String,Double)] = (0 to 127).map { c =>
        val string = xorStringSingleByte(line, c.toChar)
        val stat = chiSquaredFit(string)
        //println("char: " + c + " string: " + string + " stat: " + stat)
        (c,string,stat)
      }.toArray
      val d:Seq[(Double,String,Int)] = res.filter(!_._3.isInfinite).sortBy(_._3).take(1).map { r =>
        //println("string: " + r._2 + " score: " + r._3)
        (r._3,r._2,r._1)

      }
      d
    }.toArray
    scoreStrings.sortBy(_._1).take(1).foreach { s =>
      println("score: " + s._1 + " string: " + s._2 + " char: " + s._3)
    }
    val xorChar:Int = scoreStrings.sortBy(_._1).head._3

    val plainText = Source.fromFile("/etc/passwd").getLines.mkString
    val key = "ICE".toCharArray
    //val plainText = """Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal"""
    println("cypher: " + xorEncryptString(plainText,key))
    */
    val b64Source = Source.fromFile("/Users/tom/Scala/m2/6.txt").getLines.mkString
    println("source: " + b64Source)
    //println("hamming: " + (hammingDistance("this is a test".getBytes(), "wokka wokka!!!".getBytes())))
    val bytes = b642Bytes(b64Source)
    println("bytes length: " + bytes.size)
    val distances = (2 to 40).map { ks =>
      normalizedEditDistanceForKeySize(bytes,ks)
    }.sortBy(_._2)
    println("top 3: ")
    distances.take(3).foreach( d => println("size: " + d._1 + " distance: " + d._2))
    // break ciphertext into blocks of keysize
    val keySize = distances.head._1
    val blocks = bytes.grouped(keySize)
    val transposed = (0 to keySize-1).map { i =>
      blocks.map(_(i))
    }.toArray
    println("transposed: " + transposed)
    val keyChars = transposed.map { t =>
      println(" t size: " + t.size)
      val res:Array[(Int,String,Double)] = (0 to 127).map { c =>
        val string = xorStringSingleByte(bytes2hex(t.toArray), c.toChar)
        val stat = chiSquaredFit(string)
        println("char: " + c + " string: " + string + " stat: " + stat)
        (c,string,stat)
      }.toArray
      res.sortBy(_._3).head._1
    }
    keyChars.foreach(println)
  }

  def normalizedEditDistanceForKeySize(a:Array[Byte],size:Int): (Int,Double) = {
    val s1 = a.slice(0,size)
    val s2 = a.slice(size,size * 2)
    println("s1 size: " + s2.size)
    val d1 = hammingDistance(s1,s2)
    println("d1: " + d1 + " size: " + size)
    (size, (d1 / size.toDouble))
  }

  def chiSquaredFit(string:String): Double = {
    //println("len: " + len)
    //println("size: " + histogram.size)
    val histogram = charFrequency(string)
    val len = string.length().toDouble
    val chiSquare:Double = histogram.map { case (c,f) =>
      //println("f: " + f)
      val obs:Double = f.toDouble/len
      val exp:Double = enCharFrequency.get(c).getOrElse(0.00000000000000001)
      //println("char '" + c + "' exp: " + exp + " obs: " + obs)
      scala.math.pow((obs - exp),2) / exp
    }.filter(!_.isInfinite).sum
    Math.sqrt(chiSquare)
  }

  def hammingDistance(b1: Array[Byte], b2:Array[Byte]): Int = {
    (b1.zip(b2).map((x: (Byte, Byte)) => numberOfBitsSet((x._1 ^ x._2).toByte))).sum
  }

  def numberOfBitsSet(b: Byte) : Int = (0 to 7).map((i : Int) => (b >>> i) & 1).sum

  def charFrequency(string:String):Map[String,Int] = {
    val upper = string.toUpperCase()
    //println("string: " + upper)
    upper.toList.filter(x => (x.toChar >= 0 && x.toChar < 128)).map { c =>
      //println("c: " + c.toString + " count: " + (upper.count(_ == c)))
      c.toString -> upper.count(_ == c)
    } toMap
  }

  def bytes2b64(bytes: Array[Byte]): String = {
    java.util.Base64.getUrlEncoder.encodeToString(bytes)
  }

  def b642Bytes(string:String): Array[Byte] = {
    org.apache.commons.codec.binary.Base64.decodeBase64(string.getBytes())
  }

  def hex2Bytes(hex: String): Array[Byte] = {
    hex.sliding(2, 2).toArray.map(Integer.parseInt(_, 16).toByte)
  }

  def xor(a: Array[Byte], b: Array[Byte]): Array[Byte] = {
    require(a.length == b.length, "Byte arrays have to have the same length")

    (a.toList zip b.toList).map(elements => (elements._1 ^ elements._2).toByte).toArray
  }

  def bytes2hex(bytes: Array[Byte], sep: String = ""): String = {
    bytes.map("%02x".format(_)).mkString(sep)
  }

  def xorString(a: String, b: String): String = {
    val ab = hex2Bytes(a)
    val bb = hex2Bytes(b)
    bytes2hex(xor(bb, ab), "")
  }

  def xorSingleByte(hex: String, c: Char): Array[Byte] = {
    hex2Bytes(hex).map(b => (b ^ c).toByte)
  }

  def xorEncryptString(s:String, ca:Array[Char]): String = {
    val len = ca.size
    val out = s.toCharArray.zipWithIndex.map {
      case (x,i) => x ^ (ca(i % len))
    }
    bytes2hex(out.map(_.toByte))
  }

  def xorStringSingleByte(hex: String, c: Char): String = {
    val bytes = hex2Bytes(hex)
    new String(bytes.map(b => (b ^ c).toByte).map(_.toChar))
  }

  // returns a 128 element array with frequency of each ASCII char
  def charFrequencyHistogram(bs: Array[Byte]): Array[Long] = {
    (0 to 127).map { c =>
      bs.count(_ == c.toByte).toLong
    }.toArray
  }

}