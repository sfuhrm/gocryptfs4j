package de.sfuhrm.gocryptfs4j.nio;

import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * A {@link PathMatcher} supporting the {@code glob} and {@code regex} syntaxes.
 *
 * <p>Matching is case sensitive and performed against the path's string form
 * with {@code "/"} as the name separator.</p>
 */
final class GocryptFsPathMatcher implements PathMatcher {

    private final Pattern pattern;

    static GocryptFsPathMatcher create(String syntaxAndPattern) {
        int colon = syntaxAndPattern.indexOf(':');
        if (colon <= 0 || colon == syntaxAndPattern.length() - 1) {
            throw new IllegalArgumentException("invalid syntax-and-pattern: " + syntaxAndPattern);
        }
        String syntax = syntaxAndPattern.substring(0, colon);
        String input = syntaxAndPattern.substring(colon + 1);
        String regex;
        switch (syntax) {
            case "glob":
                regex = globToRegex(input);
                break;
            case "regex":
                regex = input;
                break;
            default:
                throw new IllegalArgumentException("unknown syntax: " + syntax);
        }
        return new GocryptFsPathMatcher(Pattern.compile(regex));
    }

    private GocryptFsPathMatcher(Pattern pattern) {
        this.pattern = pattern;
    }

    @Override
    public boolean matches(Path path) {
        return pattern.matcher(path.toString()).matches();
    }

    private static String globToRegex(String glob) {
        StringBuilder sb = new StringBuilder("^");
        int n = glob.length();
        boolean inGroup = false;
        int i = 0;
        while (i < n) {
            char c = glob.charAt(i);
            switch (c) {
                case '\\':
                    if (++i >= n) {
                        throw new PatternSyntaxException("No character to escape", glob, i - 1);
                    }
                    char next = glob.charAt(i);
                    if (isRegexMeta(next)) {
                        sb.append('\\');
                    }
                    sb.append(next);
                    break;
                case '*':
                    if (i + 1 < n && glob.charAt(i + 1) == '*') {
                        if (i + 2 < n && glob.charAt(i + 2) == '/') {
                            sb.append("(.*/)?");
                            i += 2;
                        } else {
                            sb.append(".*");
                            i++;
                        }
                    } else {
                        sb.append("[^/]*");
                    }
                    break;
                case '?':
                    sb.append("[^/]");
                    break;
                case '[': {
                    int j = i + 1;
                    if (j < n && glob.charAt(j) == '!') {
                        j++;
                    }
                    if (j < n && glob.charAt(j) == ']') {
                        j++;
                    }
                    while (j < n && glob.charAt(j) != ']') {
                        j++;
                    }
                    if (j >= n) {
                        sb.append("\\[");
                        break;
                    }
                    String cls = glob.substring(i + 1, j);
                    if (cls.startsWith("!")) {
                        cls = "^" + cls.substring(1);
                    }
                    sb.append('[').append(cls).append(']');
                    i = j;
                    break;
                }
                case '{':
                    if (inGroup) {
                        throw new PatternSyntaxException("Cannot nest groups", glob, i);
                    }
                    sb.append("(?:(?:");
                    inGroup = true;
                    break;
                case '}':
                    if (inGroup) {
                        sb.append("))");
                        inGroup = false;
                    } else {
                        sb.append('}');
                    }
                    break;
                case ',':
                    sb.append(inGroup ? ")|(?:" : ",");
                    break;
                default:
                    if (isRegexMeta(c)) {
                        sb.append('\\');
                    }
                    sb.append(c);
                    break;
            }
            i++;
        }
        if (inGroup) {
            throw new PatternSyntaxException("Missing '}'", glob, n - 1);
        }
        return sb.append('$').toString();
    }

    private static boolean isRegexMeta(char c) {
        switch (c) {
            case '.':
            case '^':
            case '$':
            case '{':
            case '}':
            case '[':
            case ']':
            case '(':
            case ')':
            case '+':
            case '|':
            case '\\':
                return true;
            default:
                return false;
        }
    }
}
