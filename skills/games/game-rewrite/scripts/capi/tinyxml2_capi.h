/* tinyxml2_capi.h - a flat C API over tinyxml2 (written against 9.0.0) so that non-C++ code (a Rust rewrite)
 * can use the same XML library as the original game. Built into tinyxml2.dll by build_libs.py (flavour
 * "dll", the library's "dll_srcs"); all functions are __cdecl and exported undecorated.
 *
 * Handles are the tinyxml2 objects themselves:  txml_doc = XMLDocument*, txml_node = XMLNode* (a document,
 * element, text, comment, declaration or unknown), txml_elem = XMLElement*, txml_attr = const XMLAttribute*,
 * txml_printer = XMLPrinter*. A txml_doc is also a txml_node (txml_doc_node). Every returned string points
 * into memory owned by the document/printer and stays valid until that object changes or is deleted.
 * NULL in, NULL out: navigation functions accept NULL and return NULL, so chains need no checks.
 */
#ifndef TINYXML2_CAPI_H
#define TINYXML2_CAPI_H

#include <stddef.h>

#if defined(_WIN32) && defined(TXML_BUILD_DLL)
#define TXML_API __declspec(dllexport)
#else
#define TXML_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct txml_doc_s txml_doc;
typedef struct txml_node_s txml_node;
typedef struct txml_elem_s txml_elem;
typedef struct txml_attr_s txml_attr;
typedef struct txml_printer_s txml_printer;

/* documents */
TXML_API txml_doc *txml_doc_new(int process_entities, int collapse_whitespace);
TXML_API void txml_doc_delete(txml_doc *doc);
TXML_API int txml_doc_parse(txml_doc *doc, const char *xml, size_t len);   /* returns XMLError, 0 = ok */
TXML_API void txml_doc_clear(txml_doc *doc);
TXML_API int txml_doc_error_id(const txml_doc *doc);
TXML_API const char *txml_doc_error_str(const txml_doc *doc);
TXML_API int txml_doc_error_line(const txml_doc *doc);
TXML_API txml_node *txml_doc_node(txml_doc *doc);
TXML_API txml_elem *txml_doc_root(txml_doc *doc);                           /* RootElement */
TXML_API txml_elem *txml_doc_new_element(txml_doc *doc, const char *name);
TXML_API txml_node *txml_doc_new_text(txml_doc *doc, const char *text);
TXML_API txml_node *txml_doc_new_comment(txml_doc *doc, const char *text);
TXML_API txml_node *txml_doc_new_declaration(txml_doc *doc, const char *text); /* NULL: default decl */
TXML_API void txml_doc_delete_node(txml_doc *doc, txml_node *node);

/* nodes (any kind) */
TXML_API const char *txml_node_value(const txml_node *node);
TXML_API txml_node *txml_node_parent(txml_node *node);
TXML_API txml_node *txml_node_first_child(txml_node *node);
TXML_API txml_node *txml_node_next_sibling(txml_node *node);
TXML_API txml_elem *txml_node_first_child_element(txml_node *node, const char *name);  /* name may be NULL */
TXML_API txml_elem *txml_node_to_element(txml_node *node);       /* NULL if not an element */
TXML_API int txml_node_is_text(const txml_node *node);
TXML_API int txml_node_is_comment(const txml_node *node);
TXML_API txml_node *txml_node_insert_end_child(txml_node *parent, txml_node *child);
TXML_API txml_node *txml_node_insert_first_child(txml_node *parent, txml_node *child);
TXML_API txml_node *txml_node_insert_after_child(txml_node *parent, txml_node *after, txml_node *child);
TXML_API void txml_node_delete_child(txml_node *parent, txml_node *child);
TXML_API void txml_node_delete_children(txml_node *parent);

/* elements */
TXML_API txml_node *txml_elem_node(txml_elem *elem);
TXML_API const char *txml_elem_name(const txml_elem *elem);
TXML_API const char *txml_elem_text(const txml_elem *elem);                /* GetText, NULL if none */
TXML_API txml_elem *txml_elem_first_child_element(txml_elem *elem, const char *name);
TXML_API txml_elem *txml_elem_next_sibling_element(txml_elem *elem, const char *name);
TXML_API const char *txml_elem_attribute(const txml_elem *elem, const char *name);   /* NULL if absent */
TXML_API int txml_elem_query_int_attribute(const txml_elem *elem, const char *name, int *out);   /* XMLError */
TXML_API int txml_elem_query_float_attribute(const txml_elem *elem, const char *name, float *out);
TXML_API int txml_elem_int_attribute(const txml_elem *elem, const char *name, int default_value);
TXML_API void txml_elem_set_attribute_str(txml_elem *elem, const char *name, const char *value);
TXML_API void txml_elem_set_attribute_int(txml_elem *elem, const char *name, int value);
TXML_API void txml_elem_delete_attribute(txml_elem *elem, const char *name);
TXML_API void txml_elem_set_text_str(txml_elem *elem, const char *text);
TXML_API void txml_elem_set_text_int(txml_elem *elem, int value);
TXML_API txml_elem *txml_elem_insert_new_child_element(txml_elem *elem, const char *name);
TXML_API const txml_attr *txml_elem_first_attribute(const txml_elem *elem);
TXML_API const txml_attr *txml_attr_next(const txml_attr *attr);
TXML_API const char *txml_attr_name(const txml_attr *attr);
TXML_API const char *txml_attr_value(const txml_attr *attr);

/* printing (XMLPrinter into memory) */
TXML_API txml_printer *txml_printer_new(int compact);
TXML_API void txml_printer_delete(txml_printer *printer);
TXML_API void txml_doc_print(txml_doc *doc, txml_printer *printer);       /* doc->Print(printer) */
TXML_API const char *txml_printer_cstr(const txml_printer *printer);
TXML_API int txml_printer_size(const txml_printer *printer);               /* bytes incl. the NUL */

/* version of the tinyxml2 sources this was built from: major*10000 + minor*100 + patch */
TXML_API int txml_version(void);

#ifdef __cplusplus
}
#endif
#endif
