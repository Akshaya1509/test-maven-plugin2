package pkg1

object Test {
  def main(args: Array[String]): Unit = {
    val s = "[2019-09-16 19:55:06,436]  INFO - lCiHP9b3Ow+U5Z7D65vp4sPtLYeiFC1tbzZEMsH7AYLxsLiI9VWnvCIxTAUXBt1D30dCPtl4PD952AOqLo98FwUxl68U1xCG/2VicFjKSd0/FLQzMzfCSYwj5vorr7Xpq5Nf8rYApoP8yfuWPZ/2L+XVJg0Yu+wv+mawZ3afVp8dp8fY7R8WUK1IZmIGYWGAGE0TlMbR3QB8KhAU4V2djCmZdu7qyQJHJcfjh+1s2QqwYFG6btKcJ4ALgfh9I6ptPF6lp0P+ZM8UxujQJ37LLisTaO03s6rVX1cxrBBo2zgpsF4cyLdbsvUb4Sm7Lq+QojACwOBF+Y9w1q5zfWuWwWQZe531qSjk7dtAsM8Offc="
    val service = EncryptionService.getInstance()
    val pattern = "(.*?)-\\s+(.*?)$".r
    // check if pattern matches before dec
    val dec = pattern.findAllIn(s).matchData.toList(0).group(2)
    println(service.decrypt(dec))
    // check if its json or xml
  }

}
