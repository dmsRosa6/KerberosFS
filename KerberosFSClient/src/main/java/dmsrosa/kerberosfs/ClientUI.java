package dmsrosa.kerberosfs;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.JTextPane;
import javax.swing.text.BadLocationException;
import javax.swing.text.Style;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;

class ClientUI {

    private final JTextPane terminalPane;
    private final JTextField commandInput;
    private final StyledDocument doc;
    private final ClientController cc;

    public ClientUI() {
        cc = new ClientController();
        JFrame frame = new JFrame("KerberosFS UI");
        frame.setSize(800, 600);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        JPanel mainPanel = new JPanel(new BorderLayout());

        // Terminal area
        terminalPane = new JTextPane();
        terminalPane.setEditable(false);
        terminalPane.setBackground(Color.DARK_GRAY);
        terminalPane.setFont(new Font("Monospaced", Font.BOLD, 19));
        doc = terminalPane.getStyledDocument();

        JScrollPane terminalScrollPane = new JScrollPane(terminalPane);
        mainPanel.add(terminalScrollPane, BorderLayout.CENTER);

        // Command input
        commandInput = new JTextField();
        commandInput.setBackground(Color.LIGHT_GRAY);
        commandInput.setForeground(Color.BLACK);
        commandInput.setFont(new Font("Monospaced", Font.BOLD, 18));
        commandInput.addActionListener(new SubmitCommandListener());

        mainPanel.add(commandInput, BorderLayout.SOUTH);

        frame.add(mainPanel);
        frame.setVisible(true);
    }

    private class SubmitCommandListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            String command = commandInput.getText().trim();
            if (command.isEmpty()) {
                appendToTerminal("> " + command, Color.WHITE);
                appendToTerminal("Command cannot be empty.", Color.RED);
                return;
            }
            // Append the command to the terminal.
            appendToTerminal("> " + command, Color.WHITE);
            try {
                CommandResponse cr = cc.executeCommand(command.split(" "));
                appendToTerminal(cr.result().isEmpty()?"No Content":cr.result(), cr.success()?Color.GREEN:Color.RED);
            } catch (Exception ex) {
                appendToTerminal(ex.getMessage(), Color.RED);
            } finally {
                commandInput.setText("");
            }
        }
    }

    private void appendToTerminal(String message, Color color) {
        Style style = terminalPane.addStyle("", null);
        StyleConstants.setForeground(style, color);
        try {
            doc.insertString(doc.getLength(), message + "\n", style);
        } catch (BadLocationException e) {
            e.printStackTrace();
        }
        terminalPane.setCaretPosition(doc.getLength());
    }
}
