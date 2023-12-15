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
        for path in path.split('/') {
            if path == ".." {
                self.dir_stack.pop();
                continue;
            }
            match self.get_node(self.get_current_group(), path) {
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
        match path {
            "" | "./" | "." => Some(NodeRef::Group(group)),
            _ => {
                let full_path = path.split('/').collect::<Vec<_>>();
                group.get(&full_path)
            }
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
