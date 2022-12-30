package burp;

import burp.model.RuleModel;
import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;
import com.intellij.uiDesigner.core.Spacer;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.List;
import java.util.function.Consumer;

/**
 * @author user
 */
public class TabShow {
    private static final String TIPS = "Enter a regular expression";
    private final RuleModel model;
    private JPanel rootPanel;
    private JButton addButton;
    private JButton removeButton;
    private JButton editButton;
    private JTable rules;
    private JScrollPane scroll;
    private JTextField address;
    private JButton saveButton;
    private int selected;

    {
// GUI initializer generated by IntelliJ IDEA GUI Designer
// >>> IMPORTANT!! <<<
// DO NOT EDIT OR ADD ANY CODE HERE!
        $$$setupUI$$$();
    }

    public TabShow() {
        selected = -1;
        scroll.setViewportView(rules);
        model = new RuleModel();

        rules.setModel(model);
        rules.getSelectionModel().addListSelectionListener(e -> selected = rules.getSelectedRow());
        addButton.addActionListener(e -> Utils.inputText(TIPS, new Consumer<>() {
            @Override
            public void accept(String s) {
                model.addRow(new String[]{s});
                onChange();
            }
        }));
        removeButton.addActionListener(e -> {
            if (selected == -1) {
                return;
            }
            model.removeRow(selected);
            selected = -1;
            onChange();
        });
        editButton.addActionListener(e -> {
            if (selected == -1) {
                return;
            }
            Utils.inputText(TIPS, new Consumer<>() {
                @Override
                public void accept(String s) {
                    model.insertRow(selected, new String[]{s});
                    model.removeRow(selected + 1);
                    onChange();
                }
            });
        });
        saveButton.addActionListener(e -> {
            String addressText = address.getText();
            if (Utils.isEmpty(addressText)) {
                return;
            }
            Bridge.getInstance().setUrl(addressText);
            onChange();
        });
    }

    /**
     * Method generated by IntelliJ IDEA GUI Designer
     * >>> IMPORTANT!! <<<
     * DO NOT edit this method OR call it in your code!
     *
     * @noinspection ALL
     */
    private void $$$setupUI$$$() {
        rootPanel = new JPanel();
        rootPanel.setLayout(new GridLayoutManager(6, 3, new Insets(0, 0, 0, 0), -1, -1));
        rootPanel.setOpaque(false);
        final JPanel panel1 = new JPanel();
        panel1.setLayout(new GridLayoutManager(5, 1, new Insets(5, 5, 5, 5), -1, -1));
        rootPanel.add(panel1, new GridConstraints(0, 0, 5, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_VERTICAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        addButton = new JButton();
        addButton.setText("Add");
        panel1.add(addButton, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, 1, null, null, null, 0, false));
        removeButton = new JButton();
        removeButton.setText("Remove");
        panel1.add(removeButton, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, 1, 1, null, null, null, 0, false));
        editButton = new JButton();
        editButton.setText("Edit");
        panel1.add(editButton, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, 1, 1, null, null, null, 0, false));
        final Spacer spacer1 = new Spacer();
        panel1.add(spacer1, new GridConstraints(3, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_VERTICAL, 1, GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        saveButton = new JButton();
        saveButton.setText("Save");
        panel1.add(saveButton, new GridConstraints(4, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel2 = new JPanel();
        panel2.setLayout(new GridBagLayout());
        rootPanel.add(panel2, new GridConstraints(0, 1, 5, 2, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        rules = new JTable();
        rules.setAutoCreateRowSorter(true);
        rules.setAutoResizeMode(4);
        rules.setCellSelectionEnabled(true);
        GridBagConstraints gbc;
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridheight = 3;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        panel2.add(rules, gbc);
        scroll = new JScrollPane();
        scroll.setVerticalScrollBarPolicy(22);
        scroll.setVisible(true);
        gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = 0;
        gbc.gridheight = 3;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        panel2.add(scroll, gbc);
        address = new JTextField();
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.gridwidth = 2;
        gbc.weightx = 1.0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        panel2.add(address, gbc);
        final Spacer spacer2 = new Spacer();
        rootPanel.add(spacer2, new GridConstraints(5, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return rootPanel;
    }

    private void onChange() {
        Bridge.getInstance().saveModel(model);
    }

    public void addData(String value) {
        model.add(value);
    }

    public void addData(List<String> value) {
        for (String each : value) {
            addData(each);
        }
    }

    public void setUrl(String url) {
        address.setText(url);
    }

    public DefaultTableModel getModel() {
        return model;
    }
}
