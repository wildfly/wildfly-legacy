/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2010, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.jboss.as.web;

/**
 * @author Emanuel Muckenhuber
 */
public interface Constants {

    String ACCESS_LOG = "access-log";
    String AJP_LISTENER = "ajp-listener";
    String ALIAS = "alias";
    String BUFFER_CACHE = "buffer-cache";
    String CA_CERTIFICATE_FILE = "ca-certificate-file";
    String CA_CERTIFICATE_PASSWORD = "ca-certificate-password";
    String CA_REVOCATION_URL = "ca-revocation-url";
    String CACHE_CONTAINER = "cache-container";
    String CACHE_NAME = "cache-name";
    String CERTIFICATE_FILE = "certificate-file";
    String CERTIFICATE_KEY_FILE = "certificate-key-file";
    String CHECK_INTERVAL = "check-interval";
    String CIPHER_SUITE = "cipher-suite";
    String CONDITION = "condition";
    String CONFIGURATION = "configuration";
    String CONNECTOR = "connector";
    String CONTAINER = "container";
    String CRAWLER_SESSION_MANAGEMENT = "crawler-session-management";
    String CUSTOM_FILTER = "custom-filter";
    String DEFAULT_HOST = "default-host";
    String DEFAULT_SESSION_TIMEOUT = "default-session-timeout";
    String DEFAULT_VIRTUAL_HOST = "default-virtual-host";
    String DEFAULT_VIRTUAL_SERVER = "default-virtual-server";
    String DEFAULT_WEB_MODULE = "default-web-module";
    String DEVELOPMENT = "development";
    String DIRECTORY = "directory";
    String DIRECTORY_LISTING = "directory-listing";
    String DISABLED = "disabled";
    String DISPLAY_SOURCE_FRAGMENT = "display-source-fragment";
    String DOMAIN = "domain";
    String DUMP_SMAP = "dump-smap";
    String ENABLED = "enabled";
    String ENABLE_LOOKUPS = "enable-lookups";
    String ENABLE_WELCOME_ROOT = "enable-welcome-root";
    String ENABLED_CIPHER_SUITES = "enabled-cipher-suites";
    String ENABLED_PROTOCOLS = "enabled-protocols";
    String ERROR_ON_USE_BEAN_INVALID_CLASS_ATTRIBUTE = "error-on-use-bean-invalid-class-attribute";
    String EXECUTOR = "executor";
    String EXPRESSION = "expression";
    String EXPRESSION_FILTER = "expression-filter";
    String EXTENDED = "extended";
    String FILE = "file";
    String FILE_ENCODING = "file-encoding";
    String FILTER = "filter";
    String FILTER_REF = "filter-ref";
    String FLAGS = "flags";
    String GENERATE_STRINGS_AS_CHAR_ARRAYS = "generate-strings-as-char-arrays";
    String HANDLER = "handler";
    String HOST = "host";
    String HTTP_LISTENER = "http-listener";
    String HTTP_ONLY = "http-only";
    String HTTPS_LISTENER = "https-listener";
    String INSTANCE_ID = "instance-id";
    String IO_SUBSYSTEM_NAME = "io";
    String LOCATION = "location";
    String JAVA_ENCODING = "java-encoding";
    String JSP = "jsp";
    String JSP_CONFIGURATION = "jsp-configuration";
    String KEEP_GENERATED = "keep-generated";
    String KEY_ALIAS = "key-alias";
    String KEYSTORE_TYPE = "keystore-type";
    String LISTINGS = "listings";
    String MAPPED_FILE = "mapped-file";
    String MAX_BUFFERED_REQUEST_SIZE = "max-buffered-request-size";
    String MAX_CONNECTIONS = "max-connections";
    String MAX_DEPTH = "max-depth";
    String MAX_POST_SIZE = "max-post-size";
    String MAX_SAVE_POST_SIZE = "max-save-post-size";
    String MIME_MAPPING = "mime-mapping";
    String MODIFICATION_TEST_INTERVAL = "modification-test-interval";
    String NAME = "name";
    String NATIVE = "native";
    String PASSWORD = "password";
    String PATH = "path";
    String PATTERN = "pattern";
    String PREDICATE = "predicate";
    String PREFIX = "prefix";
    String PROTOCOL = "protocol";
    String PROXY_BINDING = "proxy-binding";
    String PROXY_NAME = "proxy-name";
    String PROXY_PORT = "proxy-port";
    String REAUTHENTICATE = "reauthenticate";
    String READ_ONLY = "read-only";
    String RECOMPILE_ON_FAIL = "recompile-on-fail";
    String REDIRECT_BINDING = "redirect-binding";
    String REDIRECT_PORT = "redirect-port";
    String REDIRECT_SOCKET = "redirect-socket";
    String RELATIVE_TO = "relative-to";
    String RESOLVE_HOSTS = "resolve-hosts";
    String RESOLVE_PEER_ADDRESS = "resolve-peer-address";
    String REWRITE = "rewrite";
    String ROTATE = "rotate";
    String SCHEME = "scheme";
    String SCRATCH_DIR = "scratch-dir";
    String SECRET = "secret";
    String SECURE = "secure";
    String SECURITY_REALM = "security-realm";
    String SENDFILE = "sendfile";
    String SERVER = "server";
    String SERVLET_CONTAINER = "servlet-container";
    String SESSION_CACHE_SIZE = "session-cache-size";
    String SESSION_TIMEOUT = "session-timeout";
    String SINGLE_SIGN_ON = "single-sign-on";
    String SMAP = "smap";
    String SOCKET_BINDING = "socket-binding";
    String SOURCE_VM = "source-vm";
    String SSL_SESSION_CACHE_SIZE = "ssl-session-cache-size";
    String SSL_SESSION_TIMEOUT = "ssl-session-timeout";
    String SSL_PROTOCOL = "ssl-protocol";
    String SSL = "ssl";
    String SSO = "sso";
    String STATIC_RESOURCES = "static-resources";
    String SUBSTITUTION = "substitution";
    String SUBSYSTEM = "subsystem";
    String SUFFIX = "suffix";
    String SETTING = "setting";
    String TAG_POOLING = "tag-pooling";
    String TARGET_VM = "target-vm";
    String TEST = "test";
    String TRIM_SPACES = "trim-spaces";
    String TRUSTSTORE_TYPE = "truststore-type";
    String UNDERTOW_SUBSYSTEM_NAME = "undertow";
    String USER_AGENTS = "user-agents";
    String VALUE = "value";
    String VERIFY_CLIENT = "verify-client";
    String VERIFY_DEPTH = "verify-depth";
    String VIRTUAL_SERVER = "virtual-server";
    String WEBDAV = "webdav";
    String WELCOME_FILE = "welcome-file";
    String X_FORWARDED_FOR_STRING = "X-Forwarded-For";
    String X_FORWARDED_PROTO_STRING = "X-Forwarded-Proto";
    String X_POWERED_BY = "x-powered-by";

    /* Connect stats attributes */
    String BYTES_SENT = "bytesSent";
    String BYTES_RECEIVED = "bytesReceived";
    String PROCESSING_TIME = "processingTime";
    String ERROR_COUNT = "errorCount";
    String MAX_TIME = "maxTime";
    String REQUEST_COUNT = "requestCount";

    String LOAD_TIME = "load-time";
    String MIN_TIME = "min-time";
    String MODULE = "module";
    String CLASS_NAME = "class-name";
    String VALVE = "valve";
    String PARAM_NAME = "param-name";
    String PARAM_VALUE = "param-value";
    String PARAM = "param";

}
