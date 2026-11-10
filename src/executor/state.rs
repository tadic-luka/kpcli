use keepass::{
    db::{Group, Node, NodeRef},
    Database,
};
use uuid::Uuid;

pub struct State {
    pub db: Option<Db>,
}

pub struct Db {
    pub db: Database,
    // UUIDs of directory/group stack
    pub dir_stack: Vec<Uuid>,
}

impl State {
    pub fn new(db: Option<Database>) -> Self {
        Self {
            db: db.map(Db::new),
        }
    }
}

impl Db {
    fn new(db: Database) -> Self {
        Self {
            db,
            dir_stack: Vec::new(),
        }
    }

    pub fn find_group(&self, uuid: Uuid) -> Option<&Group> {
        self.db.root.iter().find_map(|n| match n {
            NodeRef::Group(g) if g.uuid == uuid => Some(g),
            _ => None,
        })
    }

    pub fn get_current_group(&self) -> &Group {
        match self.dir_stack.last() {
            None => &self.db.root,
            Some(value) => self.find_group(*value).unwrap(),
        }
    }

    pub fn change_current_group(&mut self, path: &str) -> bool {
        let previous_stack = self.dir_stack.clone();
        // absolute path, or no path at all (plain `cd`):
        // start from the root group (an empty stack)
        if path.is_empty() || path.starts_with('/') {
            self.dir_stack.clear();
        }
        for component in path.split('/') {
            if component.is_empty() || component == "." {
                continue;
            }
            if component == ".." {
                self.dir_stack.pop();
                continue;
            }
            match self.get_node(self.get_current_group(), component) {
                Some(NodeRef::Group(g)) => {
                    self.dir_stack.push(g.uuid);
                }
                Some(NodeRef::Entry(_)) | None => {
                    self.dir_stack = previous_stack;
                    return false;
                }
            }
        }
        true
    }

    pub fn get_node<'a>(&'a self, group: &'a Group, path: &str) -> Option<NodeRef<'a>> {
        // absolute path: resolve from the root group instead of `group`
        let group = if path.starts_with('/') {
            &self.db.root
        } else {
            group
        };
        let full_path: Vec<&str> = path
            .split('/')
            .filter(|s| !s.is_empty() && *s != ".")
            .collect();
        if full_path.is_empty() {
            Some(NodeRef::Group(group))
        } else {
            group.get(&full_path)
        }
    }
}

/// Whether a node with this name can be addressed by a `/`-separated path.
///
/// Path resolution (`Db::get_node`, `Db::change_current_group`) splits on `/`,
/// drops empty and `.` components and treats `..` as "parent", then matches the
/// remaining components against exact node titles. Names that cannot survive
/// that round-trip are not offered for completion.
pub fn is_addressable_name(name: &str) -> bool {
    !name.is_empty() && !name.contains('/') && name != "." && name != ".."
}

pub fn get_all_prefixes_under_group(group: &Group) -> Vec<String> {
    let mut prefixes = Vec::new();
    collect_prefixes_recursive(group, "", &mut prefixes);
    prefixes.sort();
    prefixes.dedup();
    prefixes
}

fn collect_prefixes_recursive(group: &Group, prefix: &str, out: &mut Vec<String>) {
    for child in &group.children {
        match child {
            // An unaddressable group also hides its whole subtree:
            // nothing below it can be reached by a path either.
            Node::Group(g) => {
                if is_addressable_name(&g.name) {
                    let group_path = format!("{}{}/", prefix, g.name);
                    out.push(group_path.clone());
                    collect_prefixes_recursive(g, &group_path, out);
                }
            }
            Node::Entry(e) => {
                if let Some(title) = e.get_title().filter(|t| is_addressable_name(t)) {
                    out.push(format!("{}{}", prefix, title));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepass::db::{Entry, Value};

    fn titled_entry(title: &str) -> Entry {
        let mut e = Entry::new();
        e.fields
            .insert("Title".to_string(), Value::Unprotected(title.to_string()));
        e
    }

    #[test]
    fn test_is_addressable_name() {
        assert!(is_addressable_name("Simple"));
        assert!(is_addressable_name("  padded  "));
        assert!(is_addressable_name("Bob's \"#1\" \\ bank"));
        assert!(!is_addressable_name("User / Pass"));
        assert!(!is_addressable_name(""));
        assert!(!is_addressable_name("."));
        assert!(!is_addressable_name(".."));
    }

    #[test]
    fn test_recursive_prefixes_collection() {
        let mut root = Group::new("Root");

        let mut general = Group::new("General");
        // unaddressable group: it and everything under it is skipped
        let mut slashed = Group::new("Finance / Banking");
        slashed.children.push(Node::Entry(titled_entry("Bank Account")));
        general.children.push(Node::Group(slashed));
        let mut finance = Group::new("Finance");
        finance.children.push(Node::Entry(titled_entry("Bank Account")));
        general.children.push(Node::Group(finance));
        general.children.push(Node::Entry(titled_entry("Notes")));
        general.children.push(Node::Entry(titled_entry("a/b")));
        // names are kept verbatim, no trimming
        general.children.push(Node::Entry(titled_entry(" Padded ")));

        root.children.push(Node::Group(general));

        let prefixes = get_all_prefixes_under_group(&root);
        assert_eq!(
            prefixes,
            vec![
                "General/",
                "General/ Padded ",
                "General/Finance/",
                "General/Finance/Bank Account",
                "General/Notes",
            ]
        );
    }

    #[test]
    fn test_every_indexed_prefix_resolves() {
        let mut root = Group::new("Root");
        let mut general = Group::new(" General ");
        let mut finance = Group::new("Bob's \"Bank\"");
        finance.children.push(Node::Entry(titled_entry("#1 \\ acct")));
        general.children.push(Node::Group(finance));
        general.children.push(Node::Entry(titled_entry("x/y")));
        root.children.push(Node::Group(general));
        let db = Db::new(Database::new(Default::default()));

        for prefix in get_all_prefixes_under_group(&root) {
            let node = db.get_node(&root, &prefix);
            match node {
                Some(NodeRef::Group(_)) => assert!(prefix.ends_with('/'), "{prefix}"),
                Some(NodeRef::Entry(_)) => assert!(!prefix.ends_with('/'), "{prefix}"),
                None => panic!("indexed prefix {prefix:?} does not resolve"),
            }
        }
    }

    #[test]
    fn test_absolute_paths_start_from_root() {
        let mut general = Group::new("General");
        general.children.push(Node::Group(Group::new("Finance")));
        general.children.push(Node::Entry(titled_entry("Notes")));
        let mut database = Database::new(Default::default());
        database.root.children.push(Node::Group(general));
        database.root.children.push(Node::Group(Group::new("Personal")));
        let mut db = Db::new(database);

        assert!(db.change_current_group("General/Finance"));
        assert_eq!(db.dir_stack.len(), 2);

        // absolute paths resolve from root, not from General/Finance
        assert!(matches!(
            db.get_node(db.get_current_group(), "/General/Notes"),
            Some(NodeRef::Entry(_))
        ));
        assert!(matches!(
            db.get_node(db.get_current_group(), "/"),
            Some(NodeRef::Group(g)) if g.uuid == db.db.root.uuid
        ));

        assert!(db.change_current_group("/Personal"));
        assert_eq!(db.get_current_group().name, "Personal");
        assert_eq!(db.dir_stack.len(), 1);

        // `cd /` goes back to root
        assert!(db.change_current_group("/"));
        assert!(db.dir_stack.is_empty());

        // a failed absolute cd leaves the stack untouched
        assert!(db.change_current_group("General"));
        assert!(!db.change_current_group("/Missing"));
        assert_eq!(db.get_current_group().name, "General");

        // `cd .` stays put
        assert!(db.change_current_group("."));
        assert_eq!(db.get_current_group().name, "General");

        // plain `cd` (empty path) goes back to root
        assert!(db.change_current_group("/General/Finance"));
        assert!(db.change_current_group(""));
        assert!(db.dir_stack.is_empty());
    }

    #[test]
    fn test_node_path_resolution_with_trailing_slashes() {
        let mut root = Group::new("Root");
        let mut general = Group::new("General");
        let entry = Entry::new();
        general.children.push(Node::Entry(entry));
        root.children.push(Node::Group(general));

        // Unfiltered "General/".split('/') produces ["General", ""] which fails in keepass
        assert!(root.get(&["General", ""]).is_none());

        // Filtered produces ["General"] which succeeds
        let full_path: Vec<&str> = "General/"
            .split('/')
            .filter(|s| !s.is_empty() && *s != ".")
            .collect();
        assert!(root.get(&full_path).is_some());
    }
}
