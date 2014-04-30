//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.17 at 04:06:30 PM EDT 
//


package org.mitre.cybox.common_2;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlSeeAlso;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.XmlValue;
import javax.xml.bind.annotation.adapters.HexBinaryAdapter;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import javax.xml.namespace.QName;
import org.mitre.cybox.objects.ARPCacheEntryTypeType;
import org.mitre.cybox.objects.ARPOpType;
import org.mitre.cybox.objects.AddressFamilyType;
import org.mitre.cybox.objects.ArchiveFileFormatType;
import org.mitre.cybox.objects.BitnessType;
import org.mitre.cybox.objects.BlockType;
import org.mitre.cybox.objects.ChangeLogEntryTypeType;
import org.mitre.cybox.objects.CodeLanguageType;
import org.mitre.cybox.objects.CodePurposeType;
import org.mitre.cybox.objects.CodeTypeType;
import org.mitre.cybox.objects.DNSRecordType;
import org.mitre.cybox.objects.DiskType;
import org.mitre.cybox.objects.DoNotFragmentType;
import org.mitre.cybox.objects.DomainFamilyType;
import org.mitre.cybox.objects.HTTPMethodType;
import org.mitre.cybox.objects.HandleType;
import org.mitre.cybox.objects.IANAAssignedIPNumbersType;
import org.mitre.cybox.objects.IANAEtherType;
import org.mitre.cybox.objects.IANAHardwareType;
import org.mitre.cybox.objects.IANAPortNumberRegistryType;
import org.mitre.cybox.objects.IPVersionType;
import org.mitre.cybox.objects.IPv4ClassType;
import org.mitre.cybox.objects.IPv4CopyFlagType;
import org.mitre.cybox.objects.IPv4OptionsType;
import org.mitre.cybox.objects.IPv6DoNotRecogActionType;
import org.mitre.cybox.objects.IPv6PacketChangeType;
import org.mitre.cybox.objects.ImageFileFormatType;
import org.mitre.cybox.objects.KernelHookType;
import org.mitre.cybox.objects.Layer3ProtocolType;
import org.mitre.cybox.objects.Layer7ProtocolType;
import org.mitre.cybox.objects.LibraryType;
import org.mitre.cybox.objects.MFlagType;
import org.mitre.cybox.objects.MemoryPageProtectionType;
import org.mitre.cybox.objects.MemoryPageStateType;
import org.mitre.cybox.objects.MemoryPageTypeType;
import org.mitre.cybox.objects.MoreFragmentsType;
import org.mitre.cybox.objects.NLRouteOriginType;
import org.mitre.cybox.objects.NLRouteProtocolType;
import org.mitre.cybox.objects.NetflowV9FieldType;
import org.mitre.cybox.objects.NetflowV9ScopeFieldType;
import org.mitre.cybox.objects.PEResourceContentType;
import org.mitre.cybox.objects.PEType;
import org.mitre.cybox.objects.PackerClassType;
import org.mitre.cybox.objects.PageProtectionAttributeType;
import org.mitre.cybox.objects.PageProtectionValueType;
import org.mitre.cybox.objects.PartitionType;
import org.mitre.cybox.objects.ProcessorArchType;
import org.mitre.cybox.objects.ProcessorTypeType;
import org.mitre.cybox.objects.ProtocolType;
import org.mitre.cybox.objects.RegistryDatatypeType;
import org.mitre.cybox.objects.RegistryHiveType;
import org.mitre.cybox.objects.RouteType;
import org.mitre.cybox.objects.ServiceModeType;
import org.mitre.cybox.objects.ServiceStatusType;
import org.mitre.cybox.objects.ServiceType;
import org.mitre.cybox.objects.SharedResourceType;
import org.mitre.cybox.objects.SiLKAddressType;
import org.mitre.cybox.objects.SiLKCountryCodeType;
import org.mitre.cybox.objects.SiLKDirectionType;
import org.mitre.cybox.objects.SiLKFlowAttributesType;
import org.mitre.cybox.objects.SiLKSensorClassType;
import org.mitre.cybox.objects.SocketType;
import org.mitre.cybox.objects.SubsystemType;
import org.mitre.cybox.objects.TaskActionTypeType;
import org.mitre.cybox.objects.TaskFlagType;
import org.mitre.cybox.objects.TaskPriorityType;
import org.mitre.cybox.objects.TaskStatusType;
import org.mitre.cybox.objects.TaskTriggerFrequencyType;
import org.mitre.cybox.objects.TaskTriggerType;
import org.mitre.cybox.objects.ThreadRunningStatusType;
import org.mitre.cybox.objects.UnixFileType;
import org.mitre.cybox.objects.UnixProcessStateType;
import org.mitre.cybox.objects.VolumeFileSystemFlagType;
import org.mitre.cybox.objects.WaitableTimerType;
import org.mitre.cybox.objects.WhoisStatusType;
import org.mitre.cybox.objects.WinEventType;
import org.mitre.cybox.objects.WinHookType;
import org.mitre.cybox.objects.WindowsDriveType;
import org.mitre.cybox.objects.WindowsFileAttributeType;
import org.mitre.cybox.objects.WindowsVolumeAttributeType;


/**
 * Properties that use this type can express multiple values by providing them using a delimiter-separated list. The default delimiter is '##comma##' (no quotes) but can be overridden through use of the delimiter field. Note that whitespace is preserved and so, when specifying a list of values, do not include a space following the delimiter in a list unless the first character of the next list item should, in fact, be a space.
 * 
 * <p>Java class for BaseObjectPropertyType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="BaseObjectPropertyType">
 *   &lt;simpleContent>
 *     &lt;extension base="&lt;http://www.w3.org/2001/XMLSchema>anySimpleType">
 *       &lt;attGroup ref="{http://cybox.mitre.org/common-2}BaseObjectPropertyGroup"/>
 *       &lt;attGroup ref="{http://cybox.mitre.org/common-2}PatternFieldGroup"/>
 *     &lt;/extension>
 *   &lt;/simpleContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "BaseObjectPropertyType", propOrder = {
    "value"
})
@XmlSeeAlso({
    WaitableTimerType.class,
    PropertyType.class,
    NonNegativeIntegerObjectPropertyType.class,
    DurationObjectPropertyType.class,
    EndiannessType.class,
    DoubleObjectPropertyType.class,
    LongObjectPropertyType.class,
    HexBinaryObjectPropertyType.class,
    AnyURIObjectPropertyType.class,
    SIDType.class,
    IntegerObjectPropertyType.class,
    PositiveIntegerObjectPropertyType.class,
    Layer4ProtocolType.class,
    UnsignedLongObjectPropertyType.class,
    FloatObjectPropertyType.class,
    UnsignedIntegerObjectPropertyType.class,
    DateTimeObjectPropertyRestrictionType.class,
    DateObjectPropertyRestrictionType.class,
    NameObjectPropertyType.class,
    CompensationModelType.class,
    RegionalRegistryType.class,
    CipherType.class,
    Base64BinaryObjectPropertyType.class,
    TimeObjectPropertyRestrictionType.class,
    HandleType.class,
    RouteType.class,
    ImageFileFormatType.class,
    PackerClassType.class,
    SharedResourceType.class,
    MemoryPageStateType.class,
    MemoryPageTypeType.class,
    MemoryPageProtectionType.class,
    BlockType.class,
    KernelHookType.class,
    ARPOpType.class,
    MoreFragmentsType.class,
    IPv4CopyFlagType.class,
    IPv4OptionsType.class,
    IANAHardwareType.class,
    MFlagType.class,
    IANAPortNumberRegistryType.class,
    IANAAssignedIPNumbersType.class,
    IANAEtherType.class,
    IPVersionType.class,
    IPv4ClassType.class,
    IPv6PacketChangeType.class,
    IPv6DoNotRecogActionType.class,
    DoNotFragmentType.class,
    RegistryHiveType.class,
    RegistryDatatypeType.class,
    Layer7ProtocolType.class,
    Layer3ProtocolType.class,
    HTTPMethodType.class,
    DNSRecordType.class,
    VolumeFileSystemFlagType.class,
    WhoisStatusType.class,
    ChangeLogEntryTypeType.class,
    ARPCacheEntryTypeType.class,
    BitnessType.class,
    ProcessorArchType.class,
    StringObjectPropertyType.class,
    CodeLanguageType.class,
    CodeTypeType.class,
    CodePurposeType.class,
    ProcessorTypeType.class,
    PEType.class,
    SubsystemType.class,
    PEResourceContentType.class,
    WindowsFileAttributeType.class,
    WindowsDriveType.class,
    WindowsVolumeAttributeType.class,
    ServiceType.class,
    ServiceStatusType.class,
    ServiceModeType.class,
    ThreadRunningStatusType.class,
    ArchiveFileFormatType.class,
    LibraryType.class,
    DiskType.class,
    PartitionType.class,
    TaskStatusType.class,
    TaskTriggerFrequencyType.class,
    TaskActionTypeType.class,
    TaskFlagType.class,
    TaskPriorityType.class,
    TaskTriggerType.class,
    WinEventType.class,
    UnixFileType.class,
    PageProtectionValueType.class,
    PageProtectionAttributeType.class,
    NLRouteProtocolType.class,
    NLRouteOriginType.class,
    UnixProcessStateType.class,
    ProtocolType.class,
    DomainFamilyType.class,
    SocketType.class,
    AddressFamilyType.class,
    SiLKSensorClassType.class,
    SiLKFlowAttributesType.class,
    SiLKAddressType.class,
    SiLKDirectionType.class,
    NetflowV9FieldType.class,
    NetflowV9ScopeFieldType.class,
    SiLKCountryCodeType.class,
    WinHookType.class
})
public abstract class BaseObjectPropertyType {

    @XmlValue
    @XmlSchemaType(name = "anySimpleType")
    protected Object value;
    @XmlAttribute(name = "id")
    protected QName id;
    @XmlAttribute(name = "idref")
    protected QName idref;
    @XmlAttribute(name = "datatype")
    protected DatatypeEnum datatype;
    @XmlAttribute(name = "appears_random")
    protected Boolean appearsRandom;
    @XmlAttribute(name = "is_obfuscated")
    protected Boolean isObfuscated;
    @XmlAttribute(name = "obfuscation_algorithm_ref")
    @XmlSchemaType(name = "anyURI")
    protected String obfuscationAlgorithmRef;
    @XmlAttribute(name = "is_defanged")
    protected Boolean isDefanged;
    @XmlAttribute(name = "defanging_algorithm_ref")
    @XmlSchemaType(name = "anyURI")
    protected String defangingAlgorithmRef;
    @XmlAttribute(name = "refanging_transform_type")
    protected String refangingTransformType;
    @XmlAttribute(name = "refanging_transform")
    protected String refangingTransform;
    @XmlAttribute(name = "observed_encoding")
    protected String observedEncoding;
    @XmlAttribute(name = "condition")
    protected ConditionTypeEnum condition;
    @XmlAttribute(name = "is_case_sensitive")
    protected Boolean isCaseSensitive;
    @XmlAttribute(name = "apply_condition")
    protected ConditionApplicationEnum applyCondition;
    @XmlAttribute(name = "delimiter")
    protected String delimiter;
    @XmlAttribute(name = "bit_mask")
    @XmlJavaTypeAdapter(HexBinaryAdapter.class)
    @XmlSchemaType(name = "hexBinary")
    protected byte[] bitMask;
    @XmlAttribute(name = "pattern_type")
    protected PatternTypeEnum patternType;
    @XmlAttribute(name = "regex_syntax")
    protected String regexSyntax;
    @XmlAttribute(name = "has_changed")
    protected Boolean hasChanged;
    @XmlAttribute(name = "trend")
    protected Boolean trend;

    /**
     * Gets the value of the value property.
     * 
     * @return
     *     possible object is
     *     {@link Object }
     *     
     */
    public Object getValue() {
        return value;
    }

    /**
     * Sets the value of the value property.
     * 
     * @param value
     *     allowed object is
     *     {@link Object }
     *     
     */
    public void setValue(Object value) {
        this.value = value;
    }

    /**
     * Gets the value of the id property.
     * 
     * @return
     *     possible object is
     *     {@link QName }
     *     
     */
    public QName getId() {
        return id;
    }

    /**
     * Sets the value of the id property.
     * 
     * @param value
     *     allowed object is
     *     {@link QName }
     *     
     */
    public void setId(QName value) {
        this.id = value;
    }

    /**
     * Gets the value of the idref property.
     * 
     * @return
     *     possible object is
     *     {@link QName }
     *     
     */
    public QName getIdref() {
        return idref;
    }

    /**
     * Sets the value of the idref property.
     * 
     * @param value
     *     allowed object is
     *     {@link QName }
     *     
     */
    public void setIdref(QName value) {
        this.idref = value;
    }

    /**
     * Gets the value of the datatype property.
     * 
     * @return
     *     possible object is
     *     {@link DatatypeEnum }
     *     
     */
    public DatatypeEnum getDatatype() {
        if (datatype == null) {
            return DatatypeEnum.STRING;
        } else {
            return datatype;
        }
    }

    /**
     * Sets the value of the datatype property.
     * 
     * @param value
     *     allowed object is
     *     {@link DatatypeEnum }
     *     
     */
    public void setDatatype(DatatypeEnum value) {
        this.datatype = value;
    }

    /**
     * Gets the value of the appearsRandom property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public Boolean isAppearsRandom() {
        return appearsRandom;
    }

    /**
     * Sets the value of the appearsRandom property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setAppearsRandom(Boolean value) {
        this.appearsRandom = value;
    }

    /**
     * Gets the value of the isObfuscated property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public Boolean isIsObfuscated() {
        return isObfuscated;
    }

    /**
     * Sets the value of the isObfuscated property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setIsObfuscated(Boolean value) {
        this.isObfuscated = value;
    }

    /**
     * Gets the value of the obfuscationAlgorithmRef property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getObfuscationAlgorithmRef() {
        return obfuscationAlgorithmRef;
    }

    /**
     * Sets the value of the obfuscationAlgorithmRef property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setObfuscationAlgorithmRef(String value) {
        this.obfuscationAlgorithmRef = value;
    }

    /**
     * Gets the value of the isDefanged property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public Boolean isIsDefanged() {
        return isDefanged;
    }

    /**
     * Sets the value of the isDefanged property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setIsDefanged(Boolean value) {
        this.isDefanged = value;
    }

    /**
     * Gets the value of the defangingAlgorithmRef property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getDefangingAlgorithmRef() {
        return defangingAlgorithmRef;
    }

    /**
     * Sets the value of the defangingAlgorithmRef property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setDefangingAlgorithmRef(String value) {
        this.defangingAlgorithmRef = value;
    }

    /**
     * Gets the value of the refangingTransformType property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getRefangingTransformType() {
        return refangingTransformType;
    }

    /**
     * Sets the value of the refangingTransformType property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setRefangingTransformType(String value) {
        this.refangingTransformType = value;
    }

    /**
     * Gets the value of the refangingTransform property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getRefangingTransform() {
        return refangingTransform;
    }

    /**
     * Sets the value of the refangingTransform property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setRefangingTransform(String value) {
        this.refangingTransform = value;
    }

    /**
     * Gets the value of the observedEncoding property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getObservedEncoding() {
        return observedEncoding;
    }

    /**
     * Sets the value of the observedEncoding property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setObservedEncoding(String value) {
        this.observedEncoding = value;
    }

    /**
     * Gets the value of the condition property.
     * 
     * @return
     *     possible object is
     *     {@link ConditionTypeEnum }
     *     
     */
    public ConditionTypeEnum getCondition() {
        return condition;
    }

    /**
     * Sets the value of the condition property.
     * 
     * @param value
     *     allowed object is
     *     {@link ConditionTypeEnum }
     *     
     */
    public void setCondition(ConditionTypeEnum value) {
        this.condition = value;
    }

    /**
     * Gets the value of the isCaseSensitive property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public boolean isIsCaseSensitive() {
        if (isCaseSensitive == null) {
            return true;
        } else {
            return isCaseSensitive;
        }
    }

    /**
     * Sets the value of the isCaseSensitive property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setIsCaseSensitive(Boolean value) {
        this.isCaseSensitive = value;
    }

    /**
     * Gets the value of the applyCondition property.
     * 
     * @return
     *     possible object is
     *     {@link ConditionApplicationEnum }
     *     
     */
    public ConditionApplicationEnum getApplyCondition() {
        if (applyCondition == null) {
            return ConditionApplicationEnum.ANY;
        } else {
            return applyCondition;
        }
    }

    /**
     * Sets the value of the applyCondition property.
     * 
     * @param value
     *     allowed object is
     *     {@link ConditionApplicationEnum }
     *     
     */
    public void setApplyCondition(ConditionApplicationEnum value) {
        this.applyCondition = value;
    }

    /**
     * Gets the value of the delimiter property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getDelimiter() {
        if (delimiter == null) {
            return "##comma##";
        } else {
            return delimiter;
        }
    }

    /**
     * Sets the value of the delimiter property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setDelimiter(String value) {
        this.delimiter = value;
    }

    /**
     * Gets the value of the bitMask property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public byte[] getBitMask() {
        return bitMask;
    }

    /**
     * Sets the value of the bitMask property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setBitMask(byte[] value) {
        this.bitMask = value;
    }

    /**
     * Gets the value of the patternType property.
     * 
     * @return
     *     possible object is
     *     {@link PatternTypeEnum }
     *     
     */
    public PatternTypeEnum getPatternType() {
        return patternType;
    }

    /**
     * Sets the value of the patternType property.
     * 
     * @param value
     *     allowed object is
     *     {@link PatternTypeEnum }
     *     
     */
    public void setPatternType(PatternTypeEnum value) {
        this.patternType = value;
    }

    /**
     * Gets the value of the regexSyntax property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getRegexSyntax() {
        return regexSyntax;
    }

    /**
     * Sets the value of the regexSyntax property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setRegexSyntax(String value) {
        this.regexSyntax = value;
    }

    /**
     * Gets the value of the hasChanged property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public Boolean isHasChanged() {
        return hasChanged;
    }

    /**
     * Sets the value of the hasChanged property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setHasChanged(Boolean value) {
        this.hasChanged = value;
    }

    /**
     * Gets the value of the trend property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public Boolean isTrend() {
        return trend;
    }

    /**
     * Sets the value of the trend property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setTrend(Boolean value) {
        this.trend = value;
    }

}
