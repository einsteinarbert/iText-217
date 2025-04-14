import com.lowagie.text.Document;
import com.lowagie.text.Paragraph;
import com.lowagie.text.pdf.PdfWriter;

import java.io.FileOutputStream;

/**
 * Test with jdk 1.8
 */
public class TestIText {
    public static void main(String[] args) {
        try {
            Document doc = new Document();
            PdfWriter.getInstance(doc, new FileOutputStream("test.pdf"));
            doc.open();
            doc.add(new Paragraph("Xin chào từ iText!"));
            doc.close();
            System.out.println("PDF created.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}