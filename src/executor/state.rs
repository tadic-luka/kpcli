use keepass::{Database, Group, Node, NodeRef};

pub struct State {
    pub db: Option<Db>,
}

pub struct Db {
    pub db: Database,
    // UUIDs of directory/group stack
    pub dir_stack: Vec<String>,
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

    pub fn find_group(&self, uuid: &str) -> Option<&Group> {
        self.db.root.iter().find_map(|n| match n {
            NodeRef::Group(g) if g.uuid == uuid => Some(g),
            _ => None,
        })
    }

    pub fn get_current_group(&self) -> &Group {
        match self.dir_stack.last() {
            None => &self.db.root,
            Some(value) => self.find_group(value).unwrap(),
        }
    }

    pub fn change_current_group(&mut self, path: &str) -> bool {
        let previous_stack = self.dir_stack.clone();
        for path in path.split("/") {
            if path == ".." {
                self.dir_stack.pop();
                continue;
            }
            match self.get_node(self.get_current_group(), path) {
                Some(NodeRef::Group(g)) => {
                    self.dir_stack.push(g.uuid.clone());
                }
                Some(NodeRef::Entry(_)) | None => {
                    self.dir_stack = previous_stack;
                    return false;
                }
            }
        }
        true
    }

    // recursively try to get
    pub fn get_node<'a>(&'a self, group: &'a Group, path: &str) -> Option<NodeRef<'a>> {
        fn get<'a>(group: &'a Group, path: &str) -> Option<NodeRef<'a>> {
            match path {
                "" | "./" | "." => Some(NodeRef::Group(group)),
                _ => group.children.iter().find_map(|n| match n {
                    Node::Group(g) if g.name == path => Some(n.to_ref()),
                    Node::Entry(e) => {
                        e.get_title()
                            .and_then(|t| if t == path { Some(n.to_ref()) } else { None })
                    }
                    _ => None,
                }),
            }
        }

        let mut node = group;
        for path in path.split("/") {
            match get(node, path) {
                Some(NodeRef::Group(g)) => node = g,
                Some(e @ NodeRef::Entry(_)) => return Some(e),
                None => {
                    return None;
                }
            }
        }
        Some(NodeRef::Group(node))
    }
}