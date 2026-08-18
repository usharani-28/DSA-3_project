import java.util.Scanner;

public class StringRotations {
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);

        String str = sc.nextLine();

        for (int i = 0; i < str.length(); i++) {
            System.out.println(str);
            str = str.substring(1) + str.charAt(0);
        }
    }
}
