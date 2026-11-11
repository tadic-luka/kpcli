use keepass::{
    db::{Entry, Group, Node, NodeRef},
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
        // no path at all (plain `cd`): back to the root group
        if path.is_empty() {
            self.dir_stack.clear();
            return true;
        }
        match self.walk(path) {
            Some((groups, None)) => {
                // groups[0] is the root, which is not on the stack
                self.dir_stack = groups[1..].iter().map(|g| g.uuid).collect();
                true
            }
            // the path ends on an entry, or doesn't exist
            Some((_, Some(_))) | None => false,
        }
    }

    /// Resolve `path` relative to the current group, or to the root group if
    /// it starts with `/`. An empty path is the current group itself.
    pub fn get_node(&self, path: &str) -> Option<NodeRef<'_>> {
        match self.walk(path)? {
            (_, Some(entry)) => Some(NodeRef::Entry(entry)),
            (groups, None) => groups.last().map(|g| NodeRef::Group(g)),
        }
    }

    /// Walk `path` and return the chain of groups from the root to the last
    /// group reached, plus the entry the path ends on, if it ends on one.
    ///
    /// Empty and `.` components are skipped and `..` goes to the parent group
    /// (staying at the root). The last component matches the first child with
    /// that group name or entry title; earlier components must name a group.
    fn walk(&self, path: &str) -> Option<(Vec<&Group>, Option<&Entry>)> {
        let mut groups = vec![&self.db.root];
        if !path.starts_with('/') {
            for uuid in &self.dir_stack {
                let child = groups.last()?.children.iter().find_map(|n| match n {
                    Node::Group(g) if g.uuid == *uuid => Some(g),
                    _ => None,
                })?;
                groups.push(child);
            }
        }

        let components: Vec<&str> = path
            .split('/')
            .filter(|c| !c.is_empty() && *c != ".")
            .collect();
        for (i, component) in components.iter().enumerate() {
            if *component == ".." {
                if groups.len() > 1 {
                    groups.pop();
                }
                continue;
            }
            let is_last = i + 1 == components.len();
            let current = *groups.last()?;
            if is_last {
                match current.get(&[component])? {
                    NodeRef::Group(g) => groups.push(g),
                    NodeRef::Entry(e) => return Some((groups, Some(e))),
                }
            } else {
                let child = current.children.iter().find_map(|n| match n {
                    Node::Group(g) if g.name == *component => Some(g),
                    _ => None,
                })?;
                groups.push(child);
            }
        }
        Some((groups, None))
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
        let mut general = Group::new(" General ");
        let mut finance = Group::new("Bob's \"Bank\"");
        finance.children.push(Node::Entry(titled_entry("#1 \\ acct")));
        general.children.push(Node::Group(finance));
        general.children.push(Node::Entry(titled_entry("x/y")));
        let mut database = Database::new(Default::default());
        database.root.children.push(Node::Group(general));
        let db = Db::new(database);

        for prefix in get_all_prefixes_under_group(&db.db.root) {
            let node = db.get_node(&prefix);
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
            db.get_node("/General/Notes"),
            Some(NodeRef::Entry(_))
        ));
        assert!(matches!(
            db.get_node("/"),
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

    /// Root
    /// ├── General/
    /// │   ├── Finance/
    /// │   └── Notes
    /// └── Personal/
    fn sample_db() -> Db {
        let mut general = Group::new("General");
        general.children.push(Node::Group(Group::new("Finance")));
        general.children.push(Node::Entry(titled_entry("Notes")));
        let mut database = Database::new(Default::default());
        database.root.children.push(Node::Group(general));
        let personal = Group::new("Personal");
        database.root.children.push(Node::Group(personal));
        Db::new(database)
    }

    #[test]
    fn test_change_group_to_parent() {
        let mut db = sample_db();

        assert!(db.change_current_group("General/Finance"));
        assert!(db.change_current_group(".."));
        assert_eq!(db.get_current_group().name, "General");
        assert!(db.change_current_group(".."));
        assert!(db.dir_stack.is_empty());

        // `..` at root stays at root
        assert!(db.change_current_group(".."));
        assert!(db.dir_stack.is_empty());
        assert!(db.change_current_group("../../General"));
        assert_eq!(db.get_current_group().name, "General");

        // `..` in the middle of a path
        assert!(db.change_current_group("/General/Finance/../../Personal"));
        assert_eq!(db.get_current_group().name, "Personal");
        assert_eq!(db.dir_stack.len(), 1);
    }

    #[test]
    fn test_change_group_failures_leave_stack_unchanged() {
        let mut db = sample_db();
        assert!(db.change_current_group("General"));
        let before = db.dir_stack.clone();

        // an entry is not a group
        assert!(!db.change_current_group("Notes"));
        assert_eq!(db.dir_stack, before);
        // fails part way, after `..` already popped
        assert!(!db.change_current_group("../Missing"));
        assert_eq!(db.dir_stack, before);
        // fails part way, after a group was already pushed
        assert!(!db.change_current_group("Finance/Missing"));
        assert_eq!(db.dir_stack, before);
    }

    #[test]
    fn test_get_node_relative_paths() {
        let mut db = sample_db();
        assert!(db.change_current_group("General"));

        assert!(matches!(db.get_node("Notes"), Some(NodeRef::Entry(_))));
        assert!(matches!(
            db.get_node("./Finance/"),
            Some(NodeRef::Group(g)) if g.name == "Finance"
        ));
        // empty path is the group itself
        assert!(matches!(
            db.get_node(""),
            Some(NodeRef::Group(g)) if g.name == "General"
        ));
        assert!(db.get_node("Missing").is_none());
        assert!(db.get_node("Notes/Deeper").is_none());
    }

    #[test]
    fn test_get_node_parent_paths() {
        let mut db = sample_db();
        assert!(db.change_current_group("General/Finance"));

        assert!(matches!(db.get_node("../Notes"), Some(NodeRef::Entry(_))));
        assert!(matches!(
            db.get_node("../../Personal"),
            Some(NodeRef::Group(g)) if g.name == "Personal"
        ));
        assert!(matches!(
            db.get_node(".."),
            Some(NodeRef::Group(g)) if g.name == "General"
        ));
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
