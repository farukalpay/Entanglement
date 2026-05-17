use ent_core::Label;
use proptest::prelude::*;

proptest! {
    #[test]
    fn powerset_is_generic_and_closed_under_union(mut dimensions in prop::collection::vec("[a-z]{1,4}", 1..6)) {
        dimensions.sort();
        dimensions.dedup();
        let labels = Label::powerset(&dimensions);
        prop_assert_eq!(labels.len(), 1usize << dimensions.len());

        for left in &labels {
            for right in &labels {
                let union = left.union(right);
                prop_assert!(labels.contains(&union));
                prop_assert!(left.is_subset_of(&union));
                prop_assert!(right.is_subset_of(&union));
            }
        }
    }

    #[test]
    fn complement_joins_to_grand(mut dimensions in prop::collection::vec("[a-z]{1,4}", 1..6)) {
        dimensions.sort();
        dimensions.dedup();
        let grand = Label::grand(&dimensions);
        for label in Label::powerset(&dimensions) {
            prop_assert_eq!(label.union(&label.complement(&dimensions)), grand.clone());
        }
    }
}
