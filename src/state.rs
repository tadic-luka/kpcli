use keepass::{Database, Group, Node, NodeRef};

pub struct State {
    pub db: Option<Db>,
}

pub struct Db {
    pub db: Database,
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
        Self { db }
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
