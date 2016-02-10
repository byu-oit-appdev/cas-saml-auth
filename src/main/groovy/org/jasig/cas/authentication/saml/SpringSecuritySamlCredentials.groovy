package org.jasig.cas.authentication.saml

import groovy.transform.EqualsAndHashCode
import org.jasig.cas.authentication.principal.Credentials
import org.springframework.security.saml.SAMLCredential

/**
 * {@link Credentials} class wrapping an instance of {@link org.springframework.security.saml.SAMLCredential}
 *
 * @author Dmitriy Kopylenko
 * @author JJ
 * @author Unicon, inc.
 */
@EqualsAndHashCode
class SpringSecuritySamlCredentials implements Credentials {
    final SAMLCredential samlCredential
    String whoFrom

    SpringSecuritySamlCredentials(SAMLCredential samlCredential, String whoFrom) {
        this.samlCredential = samlCredential
        this.whoFrom = whoFrom
    }

    /*
    String getSamlPrincipalId() {
        return (this.samlCredential.getAttributeByName(this.samlGroup.externalIdAttribute) ?: this.samlCredential.attributes.find {
            it.friendlyName == this.samlGroup.externalIdAttribute
        })?.DOM?.textContent
    }
     */
}
