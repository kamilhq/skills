// tinyxml2_capi.cpp - implementation of tinyxml2_capi.h (see there). Compiles with VS2010 (C++03).
#define TXML_BUILD_DLL
#include "tinyxml2_capi.h"
#include "tinyxml2.h"

using namespace tinyxml2;

#define DOC(p) reinterpret_cast<XMLDocument *>(p)
#define CDOC(p) reinterpret_cast<const XMLDocument *>(p)
#define NODE(p) reinterpret_cast<XMLNode *>(p)
#define CNODE(p) reinterpret_cast<const XMLNode *>(p)
#define ELEM(p) reinterpret_cast<XMLElement *>(p)
#define CELEM(p) reinterpret_cast<const XMLElement *>(p)
#define ATTR(p) reinterpret_cast<const XMLAttribute *>(p)
#define PRN(p) reinterpret_cast<XMLPrinter *>(p)
#define CPRN(p) reinterpret_cast<const XMLPrinter *>(p)
#define H(T, p) reinterpret_cast<T *>(p)

extern "C" {

txml_doc *txml_doc_new(int process_entities, int collapse_whitespace)
{
    return H(txml_doc, new XMLDocument(process_entities != 0,
                                       collapse_whitespace ? COLLAPSE_WHITESPACE : PRESERVE_WHITESPACE));
}
void txml_doc_delete(txml_doc *doc) { delete DOC(doc); }
int txml_doc_parse(txml_doc *doc, const char *xml, size_t len)
{
    return doc ? (int)DOC(doc)->Parse(xml, len) : (int)XML_ERROR_PARSING;
}
void txml_doc_clear(txml_doc *doc) { if (doc) DOC(doc)->Clear(); }
int txml_doc_error_id(const txml_doc *doc) { return doc ? (int)CDOC(doc)->ErrorID() : 0; }
const char *txml_doc_error_str(const txml_doc *doc) { return doc ? CDOC(doc)->ErrorStr() : 0; }
int txml_doc_error_line(const txml_doc *doc) { return doc ? CDOC(doc)->ErrorLineNum() : 0; }
txml_node *txml_doc_node(txml_doc *doc) { return H(txml_node, static_cast<XMLNode *>(DOC(doc))); }
txml_elem *txml_doc_root(txml_doc *doc) { return doc ? H(txml_elem, DOC(doc)->RootElement()) : 0; }
txml_elem *txml_doc_new_element(txml_doc *doc, const char *name)
{
    return doc ? H(txml_elem, DOC(doc)->NewElement(name)) : 0;
}
txml_node *txml_doc_new_text(txml_doc *doc, const char *text)
{
    return doc ? H(txml_node, static_cast<XMLNode *>(DOC(doc)->NewText(text))) : 0;
}
txml_node *txml_doc_new_comment(txml_doc *doc, const char *text)
{
    return doc ? H(txml_node, static_cast<XMLNode *>(DOC(doc)->NewComment(text))) : 0;
}
txml_node *txml_doc_new_declaration(txml_doc *doc, const char *text)
{
    return doc ? H(txml_node, static_cast<XMLNode *>(DOC(doc)->NewDeclaration(text))) : 0;
}
void txml_doc_delete_node(txml_doc *doc, txml_node *node) { if (doc && node) DOC(doc)->DeleteNode(NODE(node)); }

const char *txml_node_value(const txml_node *node) { return node ? CNODE(node)->Value() : 0; }
txml_node *txml_node_parent(txml_node *node) { return node ? H(txml_node, NODE(node)->Parent()) : 0; }
txml_node *txml_node_first_child(txml_node *node) { return node ? H(txml_node, NODE(node)->FirstChild()) : 0; }
txml_node *txml_node_next_sibling(txml_node *node) { return node ? H(txml_node, NODE(node)->NextSibling()) : 0; }
txml_elem *txml_node_first_child_element(txml_node *node, const char *name)
{
    return node ? H(txml_elem, NODE(node)->FirstChildElement(name)) : 0;
}
txml_elem *txml_node_to_element(txml_node *node) { return node ? H(txml_elem, NODE(node)->ToElement()) : 0; }
int txml_node_is_text(const txml_node *node) { return node && CNODE(node)->ToText() ? 1 : 0; }
int txml_node_is_comment(const txml_node *node) { return node && CNODE(node)->ToComment() ? 1 : 0; }
txml_node *txml_node_insert_end_child(txml_node *parent, txml_node *child)
{
    return parent && child ? H(txml_node, NODE(parent)->InsertEndChild(NODE(child))) : 0;
}
txml_node *txml_node_insert_first_child(txml_node *parent, txml_node *child)
{
    return parent && child ? H(txml_node, NODE(parent)->InsertFirstChild(NODE(child))) : 0;
}
txml_node *txml_node_insert_after_child(txml_node *parent, txml_node *after, txml_node *child)
{
    return parent && after && child ? H(txml_node, NODE(parent)->InsertAfterChild(NODE(after), NODE(child))) : 0;
}
void txml_node_delete_child(txml_node *parent, txml_node *child)
{
    if (parent && child) NODE(parent)->DeleteChild(NODE(child));
}
void txml_node_delete_children(txml_node *parent) { if (parent) NODE(parent)->DeleteChildren(); }

txml_node *txml_elem_node(txml_elem *elem) { return H(txml_node, static_cast<XMLNode *>(ELEM(elem))); }
const char *txml_elem_name(const txml_elem *elem) { return elem ? CELEM(elem)->Name() : 0; }
const char *txml_elem_text(const txml_elem *elem) { return elem ? CELEM(elem)->GetText() : 0; }
txml_elem *txml_elem_first_child_element(txml_elem *elem, const char *name)
{
    return elem ? H(txml_elem, ELEM(elem)->FirstChildElement(name)) : 0;
}
txml_elem *txml_elem_next_sibling_element(txml_elem *elem, const char *name)
{
    return elem ? H(txml_elem, ELEM(elem)->NextSiblingElement(name)) : 0;
}
const char *txml_elem_attribute(const txml_elem *elem, const char *name)
{
    return elem ? CELEM(elem)->Attribute(name) : 0;
}
int txml_elem_query_int_attribute(const txml_elem *elem, const char *name, int *out)
{
    return elem ? (int)CELEM(elem)->QueryIntAttribute(name, out) : (int)XML_NO_ATTRIBUTE;
}
int txml_elem_query_float_attribute(const txml_elem *elem, const char *name, float *out)
{
    return elem ? (int)CELEM(elem)->QueryFloatAttribute(name, out) : (int)XML_NO_ATTRIBUTE;
}
int txml_elem_int_attribute(const txml_elem *elem, const char *name, int default_value)
{
    return elem ? CELEM(elem)->IntAttribute(name, default_value) : default_value;
}
void txml_elem_set_attribute_str(txml_elem *elem, const char *name, const char *value)
{
    if (elem) ELEM(elem)->SetAttribute(name, value);
}
void txml_elem_set_attribute_int(txml_elem *elem, const char *name, int value)
{
    if (elem) ELEM(elem)->SetAttribute(name, value);
}
void txml_elem_delete_attribute(txml_elem *elem, const char *name) { if (elem) ELEM(elem)->DeleteAttribute(name); }
void txml_elem_set_text_str(txml_elem *elem, const char *text) { if (elem) ELEM(elem)->SetText(text); }
void txml_elem_set_text_int(txml_elem *elem, int value) { if (elem) ELEM(elem)->SetText(value); }
txml_elem *txml_elem_insert_new_child_element(txml_elem *elem, const char *name)
{
    return elem ? H(txml_elem, ELEM(elem)->InsertNewChildElement(name)) : 0;
}
const txml_attr *txml_elem_first_attribute(const txml_elem *elem)
{
    return elem ? reinterpret_cast<const txml_attr *>(CELEM(elem)->FirstAttribute()) : 0;
}
const txml_attr *txml_attr_next(const txml_attr *attr)
{
    return attr ? reinterpret_cast<const txml_attr *>(ATTR(attr)->Next()) : 0;
}
const char *txml_attr_name(const txml_attr *attr) { return attr ? ATTR(attr)->Name() : 0; }
const char *txml_attr_value(const txml_attr *attr) { return attr ? ATTR(attr)->Value() : 0; }

txml_printer *txml_printer_new(int compact) { return H(txml_printer, new XMLPrinter(0, compact != 0)); }
void txml_printer_delete(txml_printer *printer) { delete PRN(printer); }
void txml_doc_print(txml_doc *doc, txml_printer *printer) { if (doc && printer) DOC(doc)->Print(PRN(printer)); }
const char *txml_printer_cstr(const txml_printer *printer) { return printer ? CPRN(printer)->CStr() : 0; }
int txml_printer_size(const txml_printer *printer) { return printer ? CPRN(printer)->CStrSize() : 0; }

int txml_version(void)
{
    return TIXML2_MAJOR_VERSION * 10000 + TIXML2_MINOR_VERSION * 100 + TIXML2_PATCH_VERSION;
}

} // extern "C"
