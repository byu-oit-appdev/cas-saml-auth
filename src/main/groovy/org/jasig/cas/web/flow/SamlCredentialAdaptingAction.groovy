package org.jasig.cas.web.flow

import org.jasig.cas.authentication.saml.SpringSecuritySamlCredentials
import org.opensaml.saml2.core.Attribute
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.saml.SAMLCredential
import org.springframework.webflow.execution.RequestContext

/**
 * Gets the <code>SAMLCredential</code> from an existing <code>SecurityContext#Authentication</code> object available in HttpSession
 * (which is assumed to be placed there by Spring Security SAML) and wraps it
 * with CAS' <code>Credentials</code> adapter and places it in the flow scope so it could be retrieved by downstream custom
 * <code>SpringSecuritySamlAuthenticationHandler</code>. Removes SecurityContext from HttpSession after SAMLCredential has been successfully
 * retrieved.
 * <p/>
 * Also checks if the Spring Security Authentication Exception is available in HttpSession under the standard Spring Security key of
 * <i>SPRING_SECURITY_LAST_EXCEPTION</i> and in this case wraps it with <code>ExternalSamlAuthenticationException</code> and then throws it,
 * so that login flow's global transition exception handler (if such is set up) has an opportunity to handle it, for example by transitioning
 * into a custom end-state, etc.
 *
 * @author Dmitriy Kopylenko
 * @author Unicon, inc.
 */
class SamlCredentialAdaptingAction {
    private static final String SPRING_SECURITY_CONTEXT_KEY = "SPRING_SECURITY_CONTEXT"
    private static final String SPRING_SECURITY_LAST_EXCEPTION_KEY = "SPRING_SECURITY_LAST_EXCEPTION"
    private static final String CREDENTIALS_KEY = "credentials"

    protected final Logger log = LoggerFactory.getLogger(this.getClass());

    public void wrapSamlCredentialAndPlaceInFlowScope(RequestContext context, String whoFrom) {
        final def sessionMap = context.externalContext.sessionMap
        try {
            if (sessionMap.contains(SPRING_SECURITY_LAST_EXCEPTION_KEY)) {
                throw new ExternalSamlAuthenticationException(sessionMap.get(SPRING_SECURITY_LAST_EXCEPTION_KEY) as Throwable)
            }
            final def sc = sessionMap.get(SPRING_SECURITY_CONTEXT_KEY) as SecurityContext
            final def samlCredential = sc.authentication.credentials as SAMLCredential
            context.flowScope.put(
                    CREDENTIALS_KEY,
                    new SpringSecuritySamlCredentials(samlCredential, whoFrom)
            )

            if(context.flowScope.get("credentialType").equals("LDS_ACCOUNT_ID")){
                context.flowScope.put("credentialName", samlCredential.getAttributeAsString("ldsAccountID"))
                context.flowScope.put("credentialName2", samlCredential.getAttributeAsString("ldsAccountID"))
                context.flowScope.put("ldsCMISID", samlCredential.getAttributeAsString("ldsCMISID"))
                //            context.flowScope.put("preferredName", samlCredential.getAttributeAsString("preferredName"))
                context.flowScope.put("genericEmail", samlCredential.getAttributeAsString("ldsEmailAddress"))
                //            context.flowScope.put("givenName", samlCredential.getAttributeAsString("givenName"))
                context.flowScope.put("userName3", samlCredential.getAttributeAsString("cn")) //username?
                context.flowScope.put("userName2", samlCredential.getAttributeAsString("cn")) //username?
                context.flowScope.put("genericName", samlCredential.getAttributeAsString("givenName")+" "+samlCredential.getAttributeAsString("sn")) //username?
                //            context.flowScope.put("sn", samlCredential.getAttributeAsString("sn"))
            }

            if(context.flowScope.get("credentialType").equals("BYU_IDAHO_ID")||context.flowScope.get("credentialType").equals("BYU_HAWAII_ID")){
                context.flowScope.put("credentialName", samlCredential.getAttributeAsString("urn:oid:1.3.6.1.4.1.5923.1.1.1.6"))
                context.flowScope.put("credentialName2", samlCredential.getAttributeAsString("urn:oid:1.3.6.1.4.1.5923.1.1.1.6"))
                context.flowScope.put("genericEmail", samlCredential.getAttributeAsString("urn:oid:0.9.2342.19200300.100.1.3"))
                context.flowScope.put("userName3", (samlCredential.getAttributeAsString("urn:oid:2.5.4.42")+" "+samlCredential.getAttributeAsString("urn:oid:2.5.4.4")))
                context.flowScope.put("userName2", (samlCredential.getAttributeAsString("urn:oid:2.5.4.42")+" "+samlCredential.getAttributeAsString("urn:oid:2.5.4.4"))) //username?
                context.flowScope.put("genericName", (samlCredential.getAttributeAsString("urn:oid:2.5.4.42")+" "+samlCredential.getAttributeAsString("urn:oid:2.5.4.4"))) //username?
            }

        }
        finally {
            sessionMap.remove(SPRING_SECURITY_CONTEXT_KEY)
            sessionMap.remove(SPRING_SECURITY_LAST_EXCEPTION_KEY)
        }
    }

    public void wrapSamlCredentialAndPlaceInFlowScope2(RequestContext context, String whoFrom) {
        final def sessionMap = context.externalContext.sessionMap
        try {
            if (sessionMap.contains(SPRING_SECURITY_LAST_EXCEPTION_KEY)) {
                throw new ExternalSamlAuthenticationException(sessionMap.get(SPRING_SECURITY_LAST_EXCEPTION_KEY) as Throwable)
            }
            final def sc = sessionMap.get(SPRING_SECURITY_CONTEXT_KEY) as SecurityContext
            final def samlCredential = sc.authentication.credentials as SAMLCredential
            context.flowScope.put(
                    CREDENTIALS_KEY,
                    new SpringSecuritySamlCredentials(samlCredential, whoFrom)
            )

            if(context.flowScope.get("credentialType").equals("LDS_ACCOUNT_ID")) {
                context.flowScope.put("credentialName", samlCredential.getAttributeAsString("ldsAccountID"))
                context.flowScope.put("userName3", samlCredential.getAttributeAsString("cn")) //username?
            }
            if(context.flowScope.get("credentialType").equals("BYU_IDAHO_ID")||context.flowScope.get("credentialType").equals("BYU_HAWAII_ID")){
                context.flowScope.put("credentialName", samlCredential.getAttributeAsString("eduPersonPrincipalName"))
                context.flowScope.put("userName3", samlCredential.getAttributeAsString("givenName")+" "+samlCredential.getAttributeAsString("sn")) //username?
            }

        }
        finally {
            sessionMap.remove(SPRING_SECURITY_CONTEXT_KEY)
            sessionMap.remove(SPRING_SECURITY_LAST_EXCEPTION_KEY)
        }
    }
}

