import java.util.Random;
class PasswordGenerator {
public static void main(String[] args) {
Random rand = new Random();

    String pool = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{};:/?";
    int length = 15;
    StringBuilder RandomPassword = new StringBuilder();

    for (int i = 0; i < length; i++) {
            char randomChar = pool.charAt(rand.nextInt(pool.length()));
            RandomPassword.append(randomChar);
        }
    System.out.println(RandomPassword); 
  }
}