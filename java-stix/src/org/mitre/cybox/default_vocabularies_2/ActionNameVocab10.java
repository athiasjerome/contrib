//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.17 at 04:06:30 PM EDT 
//


package org.mitre.cybox.default_vocabularies_2;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;
import org.mitre.cybox.common_2.ControlledVocabularyStringType;


/**
 * NOTE: As of CybOX Version 2.1, this version of the ActionNameVocab is deprecated. Please use ActionNameVocab-1.1 instead.
 * 
 * <p>Java class for ActionNameVocab-1.0 complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="ActionNameVocab-1.0">
 *   &lt;simpleContent>
 *     &lt;restriction base="&lt;http://cybox.mitre.org/common-2>ControlledVocabularyStringType">
 *       &lt;attribute name="vocab_name" type="{http://www.w3.org/2001/XMLSchema}string" fixed="CybOX Default Action Names" />
 *       &lt;attribute name="vocab_reference" type="{http://www.w3.org/2001/XMLSchema}anyURI" fixed="http://cybox.mitre.org/XMLSchema/default_vocabularies/2.1/cybox_default_vocabularies.xsd#DefinedActionNameVocab-1.0" />
 *     &lt;/restriction>
 *   &lt;/simpleContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "ActionNameVocab-1.0")
public class ActionNameVocab10
    extends ControlledVocabularyStringType
{


}
