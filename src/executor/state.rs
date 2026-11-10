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

pub fn get_all_prefixes_under_group(group: &Group) -> Vec<String> {
    group
        .children
        .iter()
        .filter_map(|node| match node {
            Node::Group(g) => g.name.to_string().into(),
            Node::Entry(e) => e.get_title().map(String::from),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepass::db::Entry;

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
