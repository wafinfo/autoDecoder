package burp;

import burp.callback.HttpModifier;
import burp.callback.MessageEditorTabFactory;

import java.awt.*;
import java.io.File;
import java.io.PrintStream;

/**
 * @author user
 */
public class BurpExtender implements IBurpExtender, ITab {
    public static final String TAB_NAME = "autoDecoder-Beta";
    private static final String VERSION = "0.11";
    private static final String PROFILE_NAME = "autoDecoder-Beta.json";
    private TabShow show;

    /**
     * 获取配置文件路径
     *
     * @param callbacks IBurpExtenderCallbacks
     * @return 配置文件路径
     */
    public static File getPath(IBurpExtenderCallbacks callbacks) {
        String oss = System.getProperty("os.name");
        if (oss.toLowerCase().startsWith("win")) {
            return new File(PROFILE_NAME);
        }
        String jarPath = callbacks.getExtensionFilename();
        return new File(jarPath.substring(0, jarPath.lastIndexOf("/")), PROFILE_NAME);
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        Bridge instance = Bridge.getInstance();
        instance.setProfile(getPath(callbacks));
        show = instance.getShow();
        PrintStream stdout = new PrintStream(callbacks.getStdout());
        PrintStream stderr = new PrintStream(callbacks.getStderr());
        try {
            show.addData(instance.readRules());
        } catch (Exception e) {
            e.printStackTrace(stderr);
        }
        show.setUrl(instance.getUrl());
        show.setCustomFlag(instance.getFlag());

        stdout.printf("%s-%s %s\n", TAB_NAME, VERSION, "loaded");
        stdout.println("https://github.com/A5245/autoDecoder");

        callbacks.addSuiteTab(this);
        callbacks.registerHttpListener(new HttpModifier(stdout, stderr, callbacks));
        callbacks.registerMessageEditorTabFactory(new MessageEditorTabFactory(stdout, stderr, callbacks));
    }

    @Override
    public String getTabCaption() {
        return TAB_NAME;
    }

    @Override
    public Component getUiComponent() {
        return show.$$$getRootComponent$$$();
    }
}
