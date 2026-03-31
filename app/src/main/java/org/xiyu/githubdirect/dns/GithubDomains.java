package org.xiyu.githubdirect.dns;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public final class GithubDomains {

    private static final Set<String> EXACT_DOMAINS = new HashSet<>(Arrays.asList(
            "github.com",
            "api.github.com",
            "gist.github.com",
            "github.githubassets.com",
            "alive.github.com",
            "collector.github.com",
            "central.github.com",
            "copilot-proxy.githubusercontent.com",
            "github.blog"
    ));

    private static final String[] WILDCARD_SUFFIXES = {
            ".githubusercontent.com",
            ".github.io",
            ".github.com",
            ".githubassets.com"
    };

    private GithubDomains() {
    }

    public static boolean isGithubDomain(String host) {
        if (host == null || host.isEmpty()) return false;
        String lower = host.toLowerCase();
        if (lower.endsWith(".")) {
            lower = lower.substring(0, lower.length() - 1);
        }
        if (EXACT_DOMAINS.contains(lower)) return true;
        if (lower.equals("githubusercontent.com")) return true;
        if (lower.equals("github.io")) return true;
        for (String suffix : WILDCARD_SUFFIXES) {
            if (lower.endsWith(suffix)) return true;
        }
        return false;
    }

    public static Set<String> getAllDomains() {
        return new HashSet<>(EXACT_DOMAINS);
    }
}
