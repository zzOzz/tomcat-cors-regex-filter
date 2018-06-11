/**
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package fr.udl.tomcat.filters;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.res.StringManager;

public class RegexCorsFilter implements Filter {
	/** Name of the parameter that enables 'regex' mode */
	public static final String PARAM_CORS_ALLOWED_ORIGINS_REGEX = "cors.allowed.origins.regex";

	// XXX: We're hijacking the log of the original filter, to make the configuration changes for using this filter
	//      as minimal as possible.
	private static final Log log = LogFactory.getLog(CorsFilter.class);
	private static final StringManager sm = StringManager.getManager(Constants.Package);
	
	private final Set<Pattern> allowedOriginPatterns = new HashSet<>();
	private final CorsFilter corsFilter = new CorsFilter();

	@Override
	public void doFilter(final ServletRequest servletRequest, final ServletResponse servletResponse, final FilterChain filterChain) throws IOException, ServletException {
		if (!(servletRequest instanceof HttpServletRequest) || !(servletResponse instanceof HttpServletResponse)) {
			throw new ServletException(sm.getString("corsFilter.onlyHttp"));
		}

		if (!allowedOriginPatterns.isEmpty()) {
			// Check the origin, if it is matching our regular expression then add
			// that to the list of the allowed origins of the delegate CorsFilter first.
			final String origin = ((HttpServletRequest) servletRequest).getHeader(CorsFilter.REQUEST_HEADER_ORIGIN);
			if (origin != null) {
				for (Pattern allowedOriginPattern : allowedOriginPatterns) {
					if (allowedOriginPattern.matcher(origin).matches()) {
						if (corsFilter.getAllowedOrigins().add(origin)) {
							log.info("Added allowed origin " + origin);
						}
	
						break;
					}
				}
			}
		}

		corsFilter.doFilter(servletRequest, servletResponse, filterChain);
	}

	@Override
	public void init(final FilterConfig filterConfig) throws ServletException {
	    corsFilter.init(filterConfig);
		// Check whether the filter is configured for regular expressions, if so we
		// need to grab the regular expressions and a reference to the 'allowedOrigins' set.
		if (!corsFilter.isAnyOriginAllowed() && filterConfig != null && Boolean.parseBoolean(filterConfig.getInitParameter(PARAM_CORS_ALLOWED_ORIGINS_REGEX))) {
			log.info("Using regular expression matching for CORS origins");
            for (String pattern : corsFilter.getAllowedOrigins()) {
                allowedOriginPatterns.add(Pattern.compile(pattern));
			}

			corsFilter.getAllowedOrigins().clear();
		}
	}

	@Override
	public void destroy() {
		corsFilter.destroy();
	}
}
